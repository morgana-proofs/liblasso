use ark_ff::PrimeField;
use ark_std::log2;
use std::marker::PhantomData;

use super::LassoSubtable;

#[derive(Default)]
pub struct IdentitySubtable<F: PrimeField> {
  _field: PhantomData<F>,
}

impl<F: PrimeField> IdentitySubtable<F> {
  pub fn new() -> Self {
    Self {
      _field: PhantomData,
    }
  }
}

impl<F: PrimeField> LassoSubtable<F> for IdentitySubtable<F> {
  fn materialize(&self, M: usize) -> Vec<F> {
    (0..M).map(|i| F::from(i as u64)).collect()
  }

  fn evaluate_mle(&self, point: &[F]) -> F {
    let mut result = F::zero();
    for i in 0..point.len() {
      result += F::from(1u64 << i) * point[point.len() - 1 - i];
    }
    result
  }
}

#[cfg(test)]
mod test {
  use ark_curve25519::Fr;

  use crate::{
    jolt::subtable::{identity::IdentitySubtable, LassoSubtable},
    subtable_materialize_mle_parity_test,
  };

  subtable_materialize_mle_parity_test!(iden_materialize_mle_parity, IdentitySubtable<Fr>, Fr, 256);
}