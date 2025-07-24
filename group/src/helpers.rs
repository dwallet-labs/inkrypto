// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::{self_product, Error, GroupElement};
use itertools::Itertools;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;

pub mod const_generic_array_serialization;

pub trait FlatMapResults<const N: usize, T, E: fmt::Debug> {
    fn flat_map_results(self) -> Result<[T; N], E>;
}

impl<const N: usize, T, E: fmt::Debug> FlatMapResults<N, T, E> for [Result<T, E>; N] {
    fn flat_map_results(self) -> Result<[T; N], E> {
        let res: Result<Vec<T>, E> = self.into_iter().collect();

        // We know the vector is of the right size, so this is safe to unwrap.
        res.map(|vec| vec.try_into().ok().unwrap())
    }
}

impl<const N: usize, T, E: fmt::Debug> FlatMapResults<N, T, E> for Vec<Result<T, E>>
where
    E: From<Error>,
{
    fn flat_map_results(self) -> Result<[T; N], E> {
        let res: Result<Vec<T>, E> = self.into_iter().collect();

        res.and_then(|vec| {
            vec.try_into()
                .map_err(|_| E::from(Error::InvalidParameters))
        })
    }
}

/// Deduplicate and sort a vector.
pub trait DeduplicateAndSort<T> {
    /// Deduplicate and sort a vector.
    fn deduplicate_and_sort(self) -> Vec<T>;
}

impl<T: Eq + Hash + Ord, I: IntoIterator<Item = T>> DeduplicateAndSort<T> for I {
    fn deduplicate_and_sort(self) -> Vec<T> {
        let deduplicated: HashSet<_> = self.into_iter().collect();

        let mut deduplicated_and_sorted: Vec<_> = deduplicated.into_iter().collect();
        deduplicated_and_sorted.sort();

        deduplicated_and_sorted
    }
}

/// Normalize the values of a map, transitioning from an instantiated element to its value.
/// Useful for protocols in which a mapping should be sent across the wire, thus needing to be serializable.
pub trait NormalizeValues<K: Eq + Hash + Ord, G: GroupElement>:
    IntoIterator<Item = (K, G)> + Sized
{
    /// Normalize the values of a map.
    fn normalize_values(self) -> HashMap<K, G::Value> {
        let (keys, values): (Vec<_>, Vec<_>) = self.into_iter().unzip();

        // Safe to zip - the lists are of the same length, and `batch_normalize` keeps order.
        keys.into_iter().zip(G::batch_normalize(values)).collect()
    }
}

impl<K: Eq + Hash + Ord, G: GroupElement, I: IntoIterator<Item = (K, G)>> NormalizeValues<K, G>
    for I
{
}

/// Normalize the values of a map, transitioning from an instantiated element to its value.
/// Useful for protocols in which a mapping should be sent across the wire, thus needing to be serializable.
pub trait NormalizeConstGenericValues<const N: usize, K: Eq + Hash + Ord, G: GroupElement>:
    IntoIterator<Item = (K, [G; N])> + Sized
{
    /// Normalize the values of a map.
    fn normalize_const_generic_values(self) -> HashMap<K, [G::Value; N]> {
        let (keys, values): (Vec<_>, Vec<_>) = self.into_iter().unzip();

        let values = values
            .into_iter()
            .map(self_product::GroupElement::from)
            .collect();

        // Safe to zip - the lists are of the same length, and `batch_normalize` keeps order.
        keys.into_iter()
            .zip(
                self_product::GroupElement::batch_normalize(values)
                    .into_iter()
                    .map(<[G::Value; N]>::from)
                    .collect_vec(),
            )
            .collect()
    }
}

impl<const N: usize, K: Eq + Hash + Ord, G: GroupElement, I: IntoIterator<Item = (K, [G; N])>>
    NormalizeConstGenericValues<N, K, G> for I
{
}

/// Try and collect an iterator of results into a result of a hash map.
pub trait TryCollectHashMap<K: Eq + Hash + Ord, V, E: fmt::Debug>:
    IntoIterator<Item = Result<(K, V), E>> + Sized
{
    /// Try and collect an iterator of results into a result of a hash map.
    fn try_collect_hash_map(self) -> Result<HashMap<K, V>, E> {
        Ok(self
            .into_iter()
            .collect::<Result<Vec<_>, E>>()?
            .into_iter()
            .collect())
    }
}

impl<K: Eq + Hash + Ord, V, E: fmt::Debug, I: IntoIterator<Item = Result<(K, V), E>>>
    TryCollectHashMap<K, V, E> for I
{
}

/// Create a Nested Hash Map.
pub trait IntoNestedMap<
    K1: Eq + Hash + Ord,
    K2: Eq + Hash + Ord,
    V,
    T: IntoIterator<Item = (K2, V)>,
>: IntoIterator<Item = (K1, T)> + Sized
{
    /// Create a Nested Hash Map.
    fn into_nested_map(self) -> HashMap<K1, HashMap<K2, V>>;
}

/// Group into a Nested Hash Map.
pub trait GroupIntoNestedMap<K1: Eq + Hash + Ord, K2: Eq + Hash + Ord, V>:
    IntoIterator<Item = (K1, (K2, V))> + Sized
{
    /// Group into a Nested Hash Map.
    fn group_into_nested_map(self) -> HashMap<K1, HashMap<K2, V>> {
        self.into_iter().into_group_map().into_nested_map()
    }
}

impl<K1: Eq + Hash + Ord, K2: Eq + Hash + Ord, V, I: IntoIterator<Item = (K1, (K2, V))>>
    GroupIntoNestedMap<K1, K2, V> for I
{
}

impl<
        K1: Eq + Hash + Ord,
        K2: Eq + Hash + Ord,
        V,
        T: IntoIterator<Item = (K2, V)>,
        I: IntoIterator<Item = (K1, T)>,
    > IntoNestedMap<K1, K2, V, T> for I
{
    fn into_nested_map(self) -> HashMap<K1, HashMap<K2, V>> {
        self.into_iter()
            .map(|(party_id, inner)| (party_id, inner.into_iter().collect()))
            .collect()
    }
}
