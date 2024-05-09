use std::fmt::Debug;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
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

  #[derive(Debug, PartialEq, Eq, Clone)]
  pub enum TranscriptRow {
    ChallengeVector(&'static [u8], usize),
    ChallengeScalar(&'static [u8]),
    AppendedMessage(&'static [u8], &'static [u8]),
    AppendedU64(&'static [u8], u64),
  }

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
  
    pub scalars: Vec<F>,
    pub scalar_index: usize,
  
    pub vecs: Vec<Vec<F>>,
    pub vec_index: usize,

    pub log: TranscriptLog,
  }
  
  impl<F: PrimeField> TestTranscript<F> {
    pub fn new(scalar_responses: Vec<F>, vec_responses: Vec<Vec<F>>) -> Self {
      let label = b"transcript";
      Self {
        label,
        merlin_transcript: Transcript::new(label),
        scalars: scalar_responses,
        scalar_index: 0,
        vecs: vec_responses,
        vec_index: 0,
        log: TranscriptLog::Write(vec![]),
      }
    }

    pub fn as_this(other: &Self) -> Self {
      let Self {label, merlin_transcript, scalars, scalar_index, vecs, vec_index, log} = other;

      let log_records = match log {
        TranscriptLog::Write(data) => data,
        TranscriptLog::Read(data, _) => data,
      };

      Self {
        label: label,
        merlin_transcript: Transcript::new(label),
        scalars: scalars.clone(),
        scalar_index: 0,
        vecs: vecs.clone(),
        vec_index: 0,
        log: TranscriptLog::Read(log_records.clone(), 0),
      }
    }

    pub fn assert_end(&self) {
      let TranscriptLog::Read(data, idx) = &self.log else {return;};
      assert_eq!(data.len(), *idx, "Transcript length does not match");
    }
  }
  
  impl<G: CurveGroup> ProofTranscript<G> for TestTranscript<G::ScalarField> {
    fn challenge_scalar(&mut self, _label: &'static [u8]) -> G::ScalarField {
      assert!(self.scalar_index < self.scalars.len());
  
      let res = self.scalars[self.scalar_index];
      self.scalar_index += 1;

      self.log.append(TranscriptRow::ChallengeScalar(_label));
      res
    }
  
    fn challenge_vector(&mut self, _label: &'static [u8], len: usize) -> Vec<G::ScalarField> {
      assert!(self.vec_index < self.vecs.len());
  
      let res = self.vecs[self.vec_index].clone();
  
      assert_eq!(res.len(), len);
  
      self.vec_index += 1;

      self.log.append(TranscriptRow::ChallengeVector(_label, len));
      res
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
      self
        .merlin_transcript
        .append_message(b"protocol-name", protocol_name);
    }
  
    fn append_scalar(&mut self, label: &'static [u8], scalar: &G::ScalarField) {
      let mut buf = vec![];
      scalar.serialize_compressed(&mut buf).unwrap();
      self.merlin_transcript.append_message(label, &buf);
    }
  
    fn append_scalars(&mut self, label: &'static [u8], scalars: &[G::ScalarField]) {
      self
        .merlin_transcript
        .append_message(label, b"begin_append_vector");
      for item in scalars.iter() {
        <Self as ProofTranscript<G>>::append_scalar(self, label, item);
      }
      self
        .merlin_transcript
        .append_message(label, b"end_append_vector");
    }
  
    fn append_point(&mut self, label: &'static [u8], point: &G) {
      let mut buf = vec![];
      point.serialize_compressed(&mut buf).unwrap();
      self.merlin_transcript.append_message(label, &buf);
    }
  
    fn append_points(&mut self, label: &'static [u8], points: &[G]) {
      self
        .merlin_transcript
        .append_message(label, b"begin_append_vector");
      for item in points.iter() {
        self.merlin_transcript.append_point(label, item);
      }
      self
        .merlin_transcript
        .append_message(label, b"end_append_vector");
    }
  }
  