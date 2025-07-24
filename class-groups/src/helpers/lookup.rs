// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crypto_bigint::ConstantTimeSelect;

pub(crate) trait ConstantTimeLookup<T> {
    fn ct_lookup(&self, index: usize) -> CtOption<T>;
}

impl<T, const SIZE: usize> ConstantTimeLookup<T> for [T; SIZE]
where
    T: Clone + ConditionallySelectable + Default,
{
    fn ct_lookup(&self, index: usize) -> CtOption<T> {
        let none = CtOption::new(T::default(), Choice::from(0));
        self.iter()
            .enumerate()
            .map(|(idx, elt)| CtOption::new(*elt, idx.ct_eq(&index)))
            .fold(none, |acc, elt| {
                CtOption::<T>::ct_select(&acc, &elt, elt.is_some())
            })
    }
}
