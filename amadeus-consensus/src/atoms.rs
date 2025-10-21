rustler::atoms! {
    ok,
    error,
    nil,
    mutex_closed,
    busy_iterators,

    invalid_iterator,
    // Iterator control atoms
    iterator_mode,
    start,
    end,
    from,
    forward,
    reverse,
    next,


    //ama stuff because cant compile as rlib :()
    hash,
    header,
    signature,
    mask,
    txs,

    entry_signer,
    entry_prev_hash,
    entry_vr,
    entry_vr_b3,
    entry_dr,

    entry_slot,
    entry_prev_slot,
    entry_height,
    entry_epoch,

    tx,
    tx_encoded,
    signer,
    nonce,
    actions,
    op,
    contract,
    function,
    args,
    attached_symbol,
    attached_amount
}
