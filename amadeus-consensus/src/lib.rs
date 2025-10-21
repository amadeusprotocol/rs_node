pub mod consensus;
pub mod atoms;

use rustler::types::{Binary, OwnedBinary};
use rustler::{
    Encoder, Error, Env, Term, NifResult, ResourceArc, Atom,
    NifTaggedEnum
};

pub use rust_rocksdb::{TransactionDB, MultiThreaded, TransactionDBOptions, Options,
    Transaction, TransactionOptions, WriteOptions, CompactOptions, BottommostLevelCompaction,
    DBRawIteratorWithThreadMode, BoundColumnFamily,
    Cache, LruCacheOptions, BlockBasedOptions, DBCompressionType, BlockBasedIndexType,
    ColumnFamilyDescriptor, AsColumnFamilyRef};

use std::path::Path;
use std::ptr::NonNull;
use std::sync::{Mutex};


pub struct DbResource {
    pub db: TransactionDB<MultiThreaded>
}

pub struct CfResource {
    db: ResourceArc<DbResource>,
    _name: String,
    handle: NonNull<rust_librocksdb_sys::rocksdb_column_family_handle_t>,
}
unsafe impl Send for CfResource {}
unsafe impl Sync for CfResource {}
impl AsColumnFamilyRef for CfResource {
    fn inner(&self) -> *mut rust_librocksdb_sys::rocksdb_column_family_handle_t {
        self.handle.as_ptr()
    }
}

type Tx<'a> = Transaction<'a, TransactionDB<MultiThreaded>>;
pub struct TxResource {
    db: ResourceArc<DbResource>,
    tx: Mutex<Option<Tx<'static>>>,
}
unsafe impl Send for TxResource {}
unsafe impl Sync for TxResource {}


type DbIter<'a> = DBRawIteratorWithThreadMode<'a, TransactionDB<MultiThreaded>>;
type TxIter<'a> = DBRawIteratorWithThreadMode<'a, Tx<'a>>;
enum IterInner { Db(DbIter<'static>), Tx(TxIter<'static>) }
pub struct ItResource {
  db: ResourceArc<DbResource>,
  cf: Option<ResourceArc<CfResource>>,
  tx: Option<ResourceArc<TxResource>>,
  it: Mutex<IterInner>,
}
unsafe impl Send for ItResource {} unsafe impl Sync for ItResource {}

impl ItResource {
  pub fn new(
      db: ResourceArc<DbResource>,
      tx: Option<ResourceArc<TxResource>>,
      cf: Option<ResourceArc<CfResource>>,
  ) -> ResourceArc<Self> {
      let it = if let Some(txr) = &tx {
          let guard = txr.tx.lock().expect("tx mutex poisoned");
          let txn = guard.as_ref().expect("transaction missing (mutex_closed)");
          let real: TxIter<'_> = match &cf {
              Some(cf) => txn.raw_iterator_cf(&**cf),
              None     => txn.raw_iterator(),
          };
          IterInner::Tx(unsafe { std::mem::transmute::<TxIter<'_>, TxIter<'static>>(real) })
      } else {
          let real: DbIter<'_> = match &cf {
              Some(cf) => db.db.raw_iterator_cf(&**cf),
              None     => db.db.raw_iterator(),
          };
          IterInner::Db(unsafe { std::mem::transmute::<DbIter<'_>, DbIter<'static>>(real) })
      };

      ResourceArc::new(Self { db, tx, cf, it: Mutex::new(it) })
  }
}

macro_rules! with_it { ($s:expr, $it:ident => $body:expr) => {{
  let mut g = $s.it.lock().unwrap();
  match &mut *g { IterInner::Db($it) => $body, IterInner::Tx($it) => $body }
}}}

#[inline]
fn to_bin<'a>(env: Env<'a>, src: &[u8]) -> Binary<'a> {
    let mut ob = OwnedBinary::new(src.len()).expect("alloc failed");
    ob.as_mut_slice().copy_from_slice(src);
    Binary::from_owned(ob, env)
}

impl ItResource {
  pub fn seek(&self, k: &[u8])         { with_it!(self, it => it.seek(k)); }
  pub fn seek_to_first(&self)          { with_it!(self, it => it.seek_to_first()); }
  pub fn seek_to_last(&self)           { with_it!(self, it => it.seek_to_last()); }
  pub fn next(&self)                   { with_it!(self, it => it.next()); }
  pub fn prev(&self)                   { with_it!(self, it => it.prev()); }
  pub fn valid(&self) -> bool          { with_it!(self, it => it.valid()) }
  pub fn key<'a>(&self, env: Env<'a>) -> Option<Binary<'a>> { with_it!(self, it => it.key().map(|k| to_bin(env, k))) }
  pub fn val<'a>(&self, env: Env<'a>) -> Option<Binary<'a>> { with_it!(self, it => it.value().map(|v| to_bin(env, v))) }
  pub fn item<'a>(&self, env: Env<'a>) -> Option<(Binary<'a>, Binary<'a>)> {
    with_it!(self, it => match (it.key(), it.value()) {
        (Some(k), Some(v)) => Some((to_bin(env, k), to_bin(env, v))),
        _ => None,
    })
  }
}

#[allow(non_local_definitions)]
fn on_load(env: Env, _: Term) -> bool {
    let _ = rustler::resource!(DbResource, env);
    let _ = rustler::resource!(CfResource, env);
    let _ = rustler::resource!(TxResource, env);
    let _ = rustler::resource!(ItResource, env);
    true
}

fn to_nif_rdb_err(err: rust_rocksdb::Error) -> Error {
    Error::Term(Box::new(err.to_string()))
}

fn to_nif_err(err: Atom) -> Error {
    Error::Term(Box::new(err))
}

#[rustler::nif]
fn open_transaction_db<'a>(env: Env<'a>, path: String, cf_names: Vec<String>) -> NifResult<Term<'a>> {
    let mut lru_opts = LruCacheOptions::default();
    lru_opts.set_capacity(4 * 1024 * 1024 * 1024); //4GB
    lru_opts.set_num_shard_bits(8);
    let row_cache = Cache::new_lru_cache_opts(&lru_opts);

    let block_cache = Cache::new_lru_cache(4 * 1024 * 1024 * 1024); //4GB

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);
    db_opts.set_max_open_files(30000);
    //more threads
    db_opts.increase_parallelism(4);
    db_opts.set_max_background_jobs(2);

    db_opts.set_max_total_wal_size(2 * 1024 * 1024 * 1024); // 2GB
    db_opts.set_target_file_size_base(8 * 1024 * 1024 * 1024);
    //db_opts.set_target_file_size_base(2 * 1024 * 1024 * 1024);
    //db_opts.set_target_file_size_multiplier(2);
    db_opts.set_max_compaction_bytes(20 * 1024 * 1024 * 1024);

    db_opts.enable_statistics();
    db_opts.set_statistics_level(rust_rocksdb::statistics::StatsLevel::All);
    db_opts.set_skip_stats_update_on_db_open(true);

    // Bigger L0 flushes
    db_opts.set_write_buffer_size(512 * 1024 * 1024);
    db_opts.set_max_write_buffer_number(6);
    db_opts.set_min_write_buffer_number_to_merge(2);
    // L0 thresholds
    db_opts.set_level_zero_file_num_compaction_trigger(8);
    db_opts.set_level_zero_slowdown_writes_trigger(30);
    db_opts.set_level_zero_stop_writes_trigger(100);
    db_opts.set_max_subcompactions(2);

    //db_opts.set_level_compaction_dynamic_level_bytes(false);

    let mut txn_db_opts = TransactionDBOptions::default();
    txn_db_opts.set_default_lock_timeout(3000);
    txn_db_opts.set_txn_lock_timeout(3000);
    txn_db_opts.set_num_stripes(32);

    let mut cf_opts = Options::default();
    cf_opts.set_row_cache(&row_cache);

    let mut block_based_options = BlockBasedOptions::default();
    block_based_options.set_block_cache(&block_cache);

    block_based_options.set_index_type(BlockBasedIndexType::TwoLevelIndexSearch);
    block_based_options.set_partition_filters(true);
    block_based_options.set_cache_index_and_filter_blocks(true);
    block_based_options.set_cache_index_and_filter_blocks_with_high_priority(true);
    block_based_options.set_pin_top_level_index_and_filter(true);
    block_based_options.set_pin_l0_filter_and_index_blocks_in_cache(false);
    cf_opts.set_block_based_table_factory(&block_based_options);

    let dict_bytes = 32 * 1024;
    cf_opts.set_compression_per_level(&[
        DBCompressionType::None,  // L0
        DBCompressionType::None,  // L1
        DBCompressionType::Zstd,  // L2
        DBCompressionType::Zstd,  // L3
        DBCompressionType::Zstd,  // L4
        DBCompressionType::Zstd,  // L5
        DBCompressionType::Zstd,  // L6
    ]);

    cf_opts.set_compression_type(DBCompressionType::Zstd);
    cf_opts.set_compression_options(-14, 2, 0, dict_bytes);
    cf_opts.set_zstd_max_train_bytes(100 * dict_bytes);
/*
    cf_opts.set_bottommost_compression_type(DBCompressionType::Zstd);
    cf_opts.set_bottommost_compression_options(-14, 2, 0, dict_bytes, true);
    cf_opts.set_bottommost_zstd_max_train_bytes(100 * dict_bytes, true);
*/

    cf_opts.set_max_total_wal_size(2 * 1024 * 1024 * 1024); // 2GB
    cf_opts.set_target_file_size_base(8 * 1024 * 1024 * 1024);
    //cf_opts.set_target_file_size_base(2 * 1024 * 1024 * 1024);
    //cf_opts.set_target_file_size_multiplier(2);
    cf_opts.set_max_compaction_bytes(20 * 1024 * 1024 * 1024);

    // Bigger L0 flushes
    cf_opts.set_write_buffer_size(512 * 1024 * 1024);
    cf_opts.set_max_write_buffer_number(6);
    cf_opts.set_min_write_buffer_number_to_merge(2);
    // L0 thresholds
    cf_opts.set_level_zero_file_num_compaction_trigger(20);
    cf_opts.set_level_zero_slowdown_writes_trigger(40);
    cf_opts.set_level_zero_stop_writes_trigger(100);
    cf_opts.set_max_subcompactions(2);
    //cf_opts.set_periodic_compaction_seconds(0);

    //cf_opts.set_level_compaction_dynamic_level_bytes(false);

    let cf_descriptors: Vec<_> = cf_names
        .iter()
        .map(|name| ColumnFamilyDescriptor::new(name.as_str(), cf_opts.clone()))
        .collect();

    match TransactionDB::open_cf_descriptors(&db_opts, &txn_db_opts, Path::new(&path), cf_descriptors) {
        Ok(db) => {
            let resource = ResourceArc::new(DbResource { db });

            let mut out = Vec::with_capacity(cf_names.len());
            for name in cf_names {
                let cf_arc = resource
                    .db
                    .cf_handle(&name)
                    .ok_or_else(|| Error::Term(Box::new(format!("unknown column family: {}", name))))?;
                let raw = cf_arc.inner();
                let handle = NonNull::new(raw).ok_or_else(|| Error::Term(Box::new("null CF handle")))?;
                let cf_res = ResourceArc::new(CfResource {
                    db: resource.clone(),
                    _name: name.clone(),
                    handle,
                });
                out.push(cf_res);
            }

            Ok((atoms::ok(), resource, out).encode(env))
        }
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn close_db(db: ResourceArc<DbResource>) -> NifResult<Atom> {
    unsafe {
        let ptr = &db.db as *const TransactionDB<MultiThreaded> as *mut  TransactionDB<MultiThreaded>;

        //(*ptr).cancel_all_background_work(true);
        let _ = (*ptr).flush_wal(true);

        std::ptr::drop_in_place(ptr);
    }
    Ok(atoms::ok())
}

#[rustler::nif]
fn property_value<'a>(env: Env<'a>, db: ResourceArc<DbResource>, key: String) -> NifResult<Term<'a>> {
    match db.db.property_value(&key) {
        Ok(Some(value)) => {
            Ok((atoms::ok(), value).encode(env))
        },
        Ok(None) => Ok((atoms::ok(), atoms::nil()).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn property_value_cf<'a>(env: Env<'a>, cf: ResourceArc<CfResource>, key: String) -> NifResult<Term<'a>> {
    match cf.db.db.property_value_cf(&*cf, &key) {
        Ok(Some(value)) => {
            Ok((atoms::ok(), value).encode(env))
        },
        Ok(None) => Ok((atoms::ok(), atoms::nil()).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn compact_range_cf_all<'a>(env: Env<'a>, cf: ResourceArc<CfResource>) -> NifResult<Term<'a>> {
    let mut copts = CompactOptions::default();
    copts.set_exclusive_manual_compaction(false);
    copts.set_bottommost_level_compaction(BottommostLevelCompaction::ForceOptimized);

    cf.db.db
        .compact_range_cf_opt(&*cf, None::<&[u8]>, None::<&[u8]>, &copts);

    Ok(atoms::ok().encode(env))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn checkpoint(db: ResourceArc<DbResource>, path: String) -> NifResult<Atom> {
    db.db
        .create_checkpoint(&path)
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn flush_wal(db: ResourceArc<DbResource>) -> NifResult<Atom> {
    db.db
        .flush_wal(true)
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn flush(db: ResourceArc<DbResource>) -> NifResult<Atom> {
    db.db
        .flush()
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn flush_cf(cf: ResourceArc<CfResource>) -> NifResult<Atom> {
    cf.db.db
        .flush_cf(&*cf)
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn get<'a>(env: Env<'a>, db: ResourceArc<DbResource>, key: Binary) -> NifResult<Term<'a>> {
    match db.db.get(key.as_slice()) {
        Ok(Some(value)) => {
            let mut ob = OwnedBinary::new(value.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
            ob.as_mut_slice().copy_from_slice(&value);
            Ok((atoms::ok(), Binary::from_owned(ob, env)).encode(env))
        },
        Ok(None) => Ok((atoms::ok(), atoms::nil()).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn get_cf<'a>(env: Env<'a>, cf: ResourceArc<CfResource>, key: Binary) -> NifResult<Term<'a>> {
    match cf.db.db.get_cf(&*cf, key.as_slice()) {
        Ok(Some(value)) => {
            let mut ob = OwnedBinary::new(value.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
            ob.as_mut_slice().copy_from_slice(&value);
            Ok((atoms::ok(), Binary::from_owned(ob, env)).encode(env))
        },
        Ok(None) => Ok((atoms::ok(), atoms::nil()).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn put(db: ResourceArc<DbResource>, key: Binary, value: Binary) -> NifResult<Atom> {
    db.db
        .put(key.as_slice(), value.as_slice())
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn put_cf(cf: ResourceArc<CfResource>, key: Binary, value: Binary) -> NifResult<Atom> {
    cf.db.db
        .put_cf(&*cf, key.as_slice(), value.as_slice())
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn delete(db: ResourceArc<DbResource>, key: Binary) -> NifResult<Atom> {
    db.db
        .delete(key.as_slice())
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn delete_cf(cf: ResourceArc<CfResource>, key: Binary) -> NifResult<Atom> {
    cf.db.db
        .delete_cf(&*cf, key.as_slice())
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn iterator<'a>(env: Env<'a>, db: ResourceArc<DbResource>) -> NifResult<Term<'a>> {
    let res = ItResource::new(db.clone(), None, None);
    Ok((atoms::ok(), res).encode(env))
}

#[rustler::nif]
fn iterator_cf<'a>(env: Env<'a>, cf: ResourceArc<CfResource>) -> NifResult<Term<'a>> {
    let res = ItResource::new(cf.db.clone(), None, Some(cf.clone()));
    Ok((atoms::ok(), res).encode(env))
}

// Transaction
#[rustler::nif]
fn transaction<'a>(env: Env<'a>, db: ResourceArc<DbResource>) -> NifResult<Term<'a>> {
    let wopts = WriteOptions::default();
    let topts = TransactionOptions::default();

    let tx_local: Tx<'_> = db.db.transaction_opt(&wopts, &topts);
    let tx_static: Tx<'static> = unsafe { std::mem::transmute::<Tx<'_>, Tx<'static>>(tx_local) };

    Ok((atoms::ok(), ResourceArc::new(TxResource {
        db: db,
        tx: Mutex::new(Some(tx_static)),
    })).encode(env))
}

#[rustler::nif]
fn transaction_commit(tx: ResourceArc<TxResource>) -> NifResult<Atom> {
    let mut guard = tx.tx.lock().unwrap();
    let txn = guard.take().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    drop(guard); // don’t hold the lock while committing
    txn.commit().map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_rollback(tx: ResourceArc<TxResource>) -> NifResult<Atom> {
    let mut guard = tx.tx.lock().unwrap();
    let txn = guard.take().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    drop(guard);
    txn.rollback().map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_set_savepoint(tx: ResourceArc<TxResource>) -> NifResult<Atom> {
    let guard = tx.tx.lock().unwrap();
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    txn.set_savepoint();
    Ok(atoms::ok())
}

#[rustler::nif]
fn transaction_rollback_to_savepoint(tx: ResourceArc<TxResource>) -> NifResult<Atom> {
    let guard = tx.tx.lock().unwrap();
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    txn.rollback_to_savepoint()
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_get<'a>(env: Env<'a>, tx: ResourceArc<TxResource>, key: Binary) -> NifResult<Term<'a>> {
    let guard = tx.tx.lock().unwrap();
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    match txn.get(key.as_slice()) {
        Ok(Some(value)) => {
            let mut ob = OwnedBinary::new(value.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
            ob.as_mut_slice().copy_from_slice(&value);
            Ok((atoms::ok(), Binary::from_owned(ob, env)).encode(env))
        },
        Ok(None) => Ok((atoms::ok(), atoms::nil()).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn transaction_get_cf<'a>(env: Env<'a>, tx: ResourceArc<TxResource>, cf: ResourceArc<CfResource>, key: Binary) -> NifResult<Term<'a>> {
    let guard = tx.tx.lock().unwrap();
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    match txn.get_cf(&*cf, key.as_slice()) {
        Ok(Some(value)) => {
            let mut ob = OwnedBinary::new(value.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
            ob.as_mut_slice().copy_from_slice(&value);
            Ok((atoms::ok(), Binary::from_owned(ob, env)).encode(env))
        },
        Ok(None) => Ok((atoms::ok(), atoms::nil()).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn transaction_put(tx: ResourceArc<TxResource>, key: Binary, val: Binary) -> NifResult<Atom> {
    let guard = tx.tx.lock().unwrap();
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    txn.put(key.as_slice(), val.as_slice())
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_put_cf(tx: ResourceArc<TxResource>, cf: ResourceArc<CfResource>, key: Binary, val: Binary) -> NifResult<Atom> {
    let guard = tx.tx.lock().unwrap();
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    txn.put_cf(&*cf, key.as_slice(), val.as_slice())
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_delete(tx: ResourceArc<TxResource>, key: Binary) -> NifResult<Atom> {
    let guard = tx.tx.lock().unwrap();
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    txn.delete(key.as_slice())
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_delete_cf(tx: ResourceArc<TxResource>, cf: ResourceArc<CfResource>, key: Binary) -> NifResult<Atom> {
    let guard = tx.tx.lock().unwrap();
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    txn.delete_cf(&*cf, key.as_slice())
        .map(|_| atoms::ok())
        .map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_iterator<'a>(env: Env<'a>, tx: ResourceArc<TxResource>) -> NifResult<Term<'a>> {
    let res = ItResource::new(tx.db.clone(), Some(tx.clone()), None);
    Ok((atoms::ok(), res).encode(env))
}

#[rustler::nif]
fn transaction_iterator_cf<'a>(env: Env<'a>, tx: ResourceArc<TxResource>, cf: ResourceArc<CfResource>) -> NifResult<Term<'a>> {
    let res = ItResource::new(cf.db.clone(), Some(tx.clone()), Some(cf.clone()));
    Ok((atoms::ok(), res).encode(env))
}

//Iterator Generic
#[derive(NifTaggedEnum)]
pub enum IterMove<'a> {
    First,
    Last,
    Next,
    Prev,
    Seek(Binary<'a>),
    SeekForPrev(Binary<'a>)
}

fn parse_iter_move<'a>(term: Term<'a>) -> Result<IterMove<'a>, Error> {
    term.decode::<IterMove<'a>>()
}

#[rustler::nif]
fn iterator_move<'a>(env: Env<'a>, res: ResourceArc<ItResource>, action: Term<'a>) -> NifResult<Term<'a>> {
    let action = parse_iter_move(action)?;

    match action {
        IterMove::First => with_it!(res, it => it.seek_to_first()),
        IterMove::Last => with_it!(res, it => it.seek_to_last()),
        IterMove::Next => with_it!(res, it => it.next()),
        IterMove::Prev => with_it!(res, it => it.prev()),
        IterMove::Seek(ref key) => with_it!(res, it => it.seek(key.as_slice())),
        IterMove::SeekForPrev(ref key) => with_it!(res, it => it.seek_for_prev(key.as_slice())),
    }

    let mut g = res.it.lock().unwrap();
    let is_valid = match &*g {
        IterInner::Db(it) => it.valid(),
        IterInner::Tx(it) => it.valid(),
    };
    if !is_valid { return Ok((atoms::error(), atoms::invalid_iterator()).encode(env)); }

    let (k_opt, v_opt) = match &mut *g {
        IterInner::Db(it) => (it.key(), it.value()),
        IterInner::Tx(it) => (it.key(), it.value()),
    };
    match (k_opt, v_opt) {
        (Some(k), Some(v)) => {
            let mut kb = OwnedBinary::new(k.len()).ok_or_else(|| Error::Term(Box::new("alloc key")))?;
            kb.as_mut_slice().copy_from_slice(k);
            let mut vb = OwnedBinary::new(v.len()).ok_or_else(|| Error::Term(Box::new("alloc val")))?;
            vb.as_mut_slice().copy_from_slice(v);
            Ok((atoms::ok(), Binary::from_owned(kb, env), Binary::from_owned(vb, env)).encode(env))
        }
        _ => Ok((atoms::ok(), atoms::nil(), atoms::nil()).encode(env)),
    }
}

#[inline]
pub fn bcat(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut v = Vec::with_capacity(total);
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

#[inline]
pub fn fixed<const N: usize>(t: Term<'_>) -> Result<[u8; N], Error> {
    let b: Binary = t.decode()?;
    let s = b.as_slice();
    if s.len() != N { return Err(Error::BadArg); }
    let mut a = [0u8; N];
    a.copy_from_slice(s);
    Ok(a)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn apply_entry<'a>(env: Env<'a>, db: ResourceArc<DbResource>, next_entry_trimmed_map: Term<'a>, pk: Binary, sk: Binary, txs_packed2: Vec<Binary>, txus: Vec<Term<'a>>) -> Result<Term<'a>, Error> {
    let entry_signer = fixed::<48>(next_entry_trimmed_map.map_get(atoms::entry_signer())?)?;
    let entry_prev_hash = fixed::<32>(next_entry_trimmed_map.map_get(atoms::entry_prev_hash())?)?;
    let entry_vr = fixed::<96>(next_entry_trimmed_map.map_get(atoms::entry_vr())?)?;
    let entry_vr_b3 = fixed::<32>(next_entry_trimmed_map.map_get(atoms::entry_vr_b3())?)?;
    let entry_dr = fixed::<32>(next_entry_trimmed_map.map_get(atoms::entry_dr())?)?;

    let entry_slot = next_entry_trimmed_map.map_get(atoms::entry_slot())?.decode::<u64>()?;
    let entry_prev_slot = next_entry_trimmed_map.map_get(atoms::entry_prev_slot())?.decode::<u64>()?;
    let entry_height = next_entry_trimmed_map.map_get(atoms::entry_height())?.decode::<u64>()?;
    let entry_epoch = next_entry_trimmed_map.map_get(atoms::entry_epoch())?.decode::<u64>()?;

    let txs_packed = txs_packed2.into_iter().map(|b| b.as_slice().to_vec()).collect();
    consensus::consensus_apply::apply_entry(&db.db, pk.as_slice(), sk.as_slice(), &entry_signer, &entry_prev_hash, entry_slot, entry_prev_slot, entry_height, entry_epoch, &entry_vr, &entry_vr_b3, &entry_dr,
        txs_packed, txus);
    Ok((b"hi").encode(env))
}

rustler::init!("Elixir.RDB", load = on_load);
