use std::{fmt::Debug, marker::PhantomData};

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::{iterable::Iterable, test_rng};
use merlin::Transcript;
use rand_chacha::rand_core::RngCore;

use crate::utils::transcript::ProofTranscript;


pub fn gen_random_points<F: PrimeField, const C: usize>(memory_bits: usize) -> [Vec<F>; C] {
    std::array::from_fn(|_| gen_random_point(memory_bits))
  }
  
  pub fn gen_random_point<F: PrimeField>(memory_bits: usize) -> Vec<F> {
    let mut rng = test_rng();
    let mut r_i: Vec<F> = Vec::with_capacity(memory_bits);
    for _ in 0..memory_bits {
      r_i.push(F::rand(&mut rng));
    }
    r_i
  }
  
  pub fn gen_indices<const C: usize>(sparsity: usize, memory_size: usize) -> Vec<[usize; C]> {
    let mut rng = test_rng();
    let mut all_indices: Vec<[usize; C]> = Vec::new();
    for _ in 0..sparsity {
      let indices = [rng.next_u64() as usize % memory_size; C];
      all_indices.push(indices);
    }
    all_indices
  }

  #[derive(PartialEq, Eq, Clone)]
  pub enum TranscriptRow {
    ChallengeVector(&'static [u8], usize),
    ChallengeScalar(&'static [u8]),
    AppendedMessage(&'static [u8], &'static [u8]),
    AppendedU64(&'static [u8], u64),
    AppendedGeneric(&'static [u8], Vec<u8>),
  }

  impl Debug for TranscriptRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChallengeVector(arg0, arg1) => f.debug_tuple("ChallengeVector").field(&arg0.iter().map(|&c| char::from(c)).collect::<String>()).field(arg1).finish(),
            Self::ChallengeScalar(arg0) => f.debug_tuple("ChallengeScalar").field(&arg0.iter().map(|&c| char::from(c)).collect::<String>()).finish(),
            Self::AppendedMessage(arg0, arg1) => f.debug_tuple("AppendedMessage").field(&arg0.iter().map(|&c| char::from(c)).collect::<String>()).field(&arg1.iter().map(|&c| char::from(c)).collect::<String>()).finish(),
            Self::AppendedU64(arg0, arg1) => f.debug_tuple("AppendedU64").field(&arg0.iter().map(|&c| char::from(c)).collect::<String>()).field(arg1).finish(),
            Self::AppendedGeneric(arg0, arg1) => f.debug_tuple("AppendGeneric").field(&arg0.iter().map(|&c| char::from(c)).collect::<String>()).field(arg1).finish(),
        }
    }
  }

  #[derive(Debug, PartialEq, Eq, Clone)]
  pub enum TranscriptLog {
    Write(Vec<TranscriptRow>),
    Read(Vec<TranscriptRow>, usize)
  }


  impl TranscriptLog {
    pub fn append(&mut self, row: TranscriptRow) {
      match self {
        TranscriptLog::Write(rows) => rows.push(row),
        TranscriptLog::Read(rows, idx) => {
          assert_eq!(rows[*idx], row);
          *idx += 1;
        },
      }
    }
  }


  /// Wrapper around merlin_transcript that allows overriding
  pub struct TestTranscript<F: Debug + Eq> {
    pub label: &'static [u8],
    pub merlin_transcript: Transcript,
    pub log: TranscriptLog,
    _pd: PhantomData<F>
  }
  
  impl<F: PrimeField> TestTranscript<F> {
    pub fn new() -> Self {
      let label = b"transcript";
      Self {
        label,
        merlin_transcript: Transcript::new(label),
        log: TranscriptLog::Write(vec![]),
        _pd: PhantomData,
      }
    }

    fn _append_message(&mut self, label: &'static [u8], msg: Vec<u8>) {
      self.merlin_transcript.append_message(label, &msg);
      self.log.append(TranscriptRow::AppendedGeneric(label, msg));
    }

    pub fn as_this(other: &Self) -> Self {
      let Self {label, merlin_transcript, log, _pd: _} = other;

      let log_records = match log {
        TranscriptLog::Write(data) => data,
        TranscriptLog::Read(data, _) => data,
      };

      Self {
        label: label,
        merlin_transcript: Transcript::new(label),
        log: TranscriptLog::Read(log_records.clone(), 0),
        _pd: PhantomData,
      }
    }

    pub fn assert_end(&self) {
      let TranscriptLog::Read(data, idx) = &self.log else {return;};
      assert_eq!(data.len(), *idx, "Transcript length does not match");
    }
  }
  
  impl<G: CurveGroup> ProofTranscript<G> for TestTranscript<G::ScalarField> {
    fn challenge_scalar(&mut self, _label: &'static [u8]) -> G::ScalarField {
      self.log.append(TranscriptRow::ChallengeScalar(_label));
      <Transcript as ProofTranscript<G>>::challenge_scalar(&mut self.merlin_transcript, _label)
    }
  
    fn challenge_vector(&mut self, _label: &'static [u8], len: usize) -> Vec<G::ScalarField> {
      self.log.append(TranscriptRow::ChallengeVector(_label, len));
      <Transcript as ProofTranscript<G>>::challenge_vector(&mut self.merlin_transcript, _label, len)
    }
  
    // The following match impl ProofTranscript for Transcript, but do not affect challenge responses
  
    fn append_message(&mut self, label: &'static [u8], msg: &'static [u8]) {
      self.merlin_transcript.append_message(label, msg);
      self.log.append(TranscriptRow::AppendedMessage(label, msg));
    }
  
    fn append_u64(&mut self, label: &'static [u8], x: u64) {
      self.merlin_transcript.append_u64(label, x);
      self.log.append(TranscriptRow::AppendedU64(label, x));
    }
  
    fn append_protocol_name(&mut self, protocol_name: &'static [u8]) {
      self._append_message(b"protocol-name", protocol_name.to_vec());
    }
  
    fn append_scalar(&mut self, label: &'static [u8], scalar: &G::ScalarField) {
      let mut buf = vec![];
      scalar.serialize_compressed(&mut buf).unwrap();
      self._append_message(label, buf);
    }
  
    fn append_scalars(&mut self, label: &'static [u8], scalars: &[G::ScalarField]) {
      <Self as ProofTranscript<G>>::append_message(self, label, b"begin_append_vector");
      for item in scalars.iter() {
        <Self as ProofTranscript<G>>::append_scalar(self, label, item);
      }
      <Self as ProofTranscript<G>>::append_message(self, label, b"end_append_vector");
    }
  
    fn append_point(&mut self, label: &'static [u8], point: &G) {
      let mut buf = vec![];
      point.serialize_compressed(&mut buf).unwrap();
      self._append_message(label, buf);
    }
  
    fn append_points(&mut self, label: &'static [u8], points: &[G]) {
      <Self as ProofTranscript<G>>::append_message(self, label, b"begin_append_vector");
      for item in points.iter() {
        self.append_point(label, item);
      }
      <Self as ProofTranscript<G>>::append_message(self, label, b"end_append_vector");
    }
  }
  