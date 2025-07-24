// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use std::cmp::min;

use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crypto_bigint::ConstantTimeSelect;

pub(crate) trait ConstantTimeLookup {
    type Item;

    /// Retrieve the element at `index` in constant time.
    ///
    /// Assumes `index` is a valid index; returns `None` otherwise.
    fn ct_lookup(&self, index: usize) -> CtOption<Self::Item>;

    /// Retrieve the element at `index` in constant time.
    ///
    /// Assumes `index ≤ bound`; returns `None` otherwise.
    ///
    /// Executes in variable time w.r.t. `bound`.
    fn ct_bounded_lookup(&self, index: usize, bound: usize) -> CtOption<Self::Item>;
}

impl<T> ConstantTimeLookup for [T]
where
    T: Clone + ConditionallySelectable + Default,
{
    type Item = T;

    fn ct_lookup(&self, index: usize) -> CtOption<T> {
        self.ct_bounded_lookup(index, self.as_ref().len())
    }

    fn ct_bounded_lookup(&self, index: usize, bound: usize) -> CtOption<T> {
        let none = CtOption::new(T::default(), Choice::from(0));
        self[0..=min(bound, self.as_ref().len().saturating_sub(1))]
            .iter()
            .enumerate()
            .map(|(idx, elt)| CtOption::new(*elt, idx.ct_eq(&index)))
            .fold(none, |acc, elt| {
                CtOption::<T>::ct_select(&acc, &elt, elt.is_some())
            })
    }
}

impl<T> ConstantTimeLookup for Vec<T>
where
    T: Clone + ConditionallySelectable + Default + Iterator + AsRef<[T]>,
{
    type Item = T;

    fn ct_lookup(&self, index: usize) -> CtOption<Self::Item> {
        self.as_slice().ct_lookup(index)
    }

    fn ct_bounded_lookup(&self, index: usize, bound: usize) -> CtOption<Self::Item> {
        self.as_slice().ct_bounded_lookup(index, bound)
    }
}

#[cfg(test)]
mod tests {
    use crate::helpers::lookup::ConstantTimeLookup;

    #[test]
    fn test_ct_lookup() {
        let arr: [_; 32] = core::array::from_fn(|x| x as u32);
        assert_eq!(arr.ct_lookup(0).unwrap(), 0);
        assert_eq!(arr.ct_lookup(5).unwrap(), 5);
        assert_eq!(arr.ct_lookup(31).unwrap(), 31);
        assert!(bool::from(arr.ct_lookup(32).is_none()));
    }

    #[test]
    fn test_ct_bounded_lookup() {
        let arr: [_; 32] = core::array::from_fn(|x| x as u32);
        assert_eq!(arr.ct_bounded_lookup(0, 17).unwrap(), 0);
        assert_eq!(arr.ct_bounded_lookup(5, 17).unwrap(), 5);
        assert_eq!(arr.ct_bounded_lookup(17, 17).unwrap(), 17);
        assert!(bool::from(arr.ct_bounded_lookup(18, 17).is_none()));
        assert!(bool::from(arr.ct_bounded_lookup(31, 17).is_none()));
    }
}
