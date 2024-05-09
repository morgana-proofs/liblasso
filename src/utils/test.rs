use ark_curve25519::{EdwardsProjective as G1Projective, Fr};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::utils::test_lib::*;
use crate::utils::transcript::ProofTranscript;

#[test]
fn test_transcript() {
  let scalars = vec![Fr::from(10), Fr::from(20), Fr::from(30)];
  let vecs = vec![
    vec![Fr::from(10), Fr::from(20), Fr::from(30)],
    vec![Fr::from(40), Fr::from(50), Fr::from(60)],
  ];
  let mut transcript = TestTranscript::new(scalars.clone(), vecs);

  verify_scalars::<G1Projective, Fr, _>(&mut transcript, scalars);
}

fn verify_scalars<G: CurveGroup, F: PrimeField, T: ProofTranscript<G>>(
  transcript: &mut T,
  scalars: Vec<G::ScalarField>,
) {
  for scalar in scalars {
    let challenge: G::ScalarField = transcript.challenge_scalar(b"oi-mate");
    assert_eq!(challenge, scalar);
  }
}

fn verify_vecs<G: CurveGroup, F: PrimeField, T: ProofTranscript<G>>(
  transcript: &mut T,
  vecs: Vec<Vec<G::ScalarField>>,
) {
  for vec in vecs {
    let challenge: Vec<G::ScalarField> = transcript.challenge_vector(b"ahoy-mate", vec.len());
    assert_eq!(challenge, vec);
  }
}
