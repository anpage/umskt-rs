#![macro_use]

use std::ops::{BitAnd, Shl, Shr};

use num_traits::Num;

#[inline(always)]
pub(crate) fn bitmask<N>(n: N) -> N
where
    N: Num + Shl<Output = N>,
{
    (N::one() << n) - N::one()
}

#[inline(always)]
pub(crate) fn extract_bits<N>(field: N, n: N, offset: N) -> N
where
    N: Num + BitAnd<Output = N> + Shr<Output = N> + Shl<Output = N>,
{
    (field >> offset) & bitmask(n)
}

#[inline(always)]
pub(crate) fn extract_ls_bits<N>(field: N, n: N) -> N
where
    N: Num + BitAnd<Output = N> + Shl<Output = N>,
{
    field & bitmask(n)
}
