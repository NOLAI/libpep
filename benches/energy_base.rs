use energy_bench::EnergyBenchBuilder;
use libpep::arithmetic::group_elements::{GroupElement, G};
use libpep::arithmetic::scalars::ScalarNonZero;
use libpep::core::elgamal::{decrypt, encrypt};
use libpep::core::primitives::{
    rekey, rekey2, rerandomize, reshuffle, reshuffle2, rrsk, rrsk2, rsk, rsk2,
};
use rand::rng;

struct BenchMetadata {
    operation: &'static str,
    iterations: usize,
}

impl energy_bench::Metadata<2> for BenchMetadata {
    fn get_header() -> [&'static str; 2] {
        ["Operation", "Iterations"]
    }

    fn get_values(&self) -> [String; 2] {
        [self.operation.to_string(), self.iterations.to_string()]
    }
}

fn setup_keys() -> (ScalarNonZero, GroupElement) {
    let mut rng = rng();
    let secret_key = ScalarNonZero::random(&mut rng);
    let public_key = secret_key * G;
    (secret_key, public_key)
}

fn main() {
    let mut builder = EnergyBenchBuilder::new("libpep_base_operations");
    builder.set_number_of_runs(10);
    let mut bench = builder.build();

    let iterations = 10_000;

    // Benchmark encrypt
    {
        let (_, public_key) = setup_keys();
        let mut rng = rng();
        let message = GroupElement::random(&mut rng);

        let metadata = BenchMetadata {
            operation: "encrypt",
            iterations,
        };

        bench.benchmark::<(), ()>(metadata, &|| {
            for _ in 0..iterations {
                let mut rng_inner = rand::rng();
                let _ = encrypt(&message, &public_key, &mut rng_inner);
            }
            Ok(())
        });
    }

    // Benchmark decrypt
    {
        let (secret_key, public_key) = setup_keys();
        let mut rng = rng();
        let message = GroupElement::random(&mut rng);
        let encrypted = encrypt(&message, &public_key, &mut rng);

        let metadata = BenchMetadata {
            operation: "decrypt",
            iterations,
        };

        bench.benchmark::<(), ()>(metadata, &|| {
            for _ in 0..iterations {
                let _ = decrypt(&encrypted, &secret_key);
            }
            Ok(())
        });
    }

    // Benchmark rerandomize
    {
        let (_, public_key) = setup_keys();
        let mut rng = rng();
        let message = GroupElement::random(&mut rng);
        let encrypted = encrypt(&message, &public_key, &mut rng);
        let r = ScalarNonZero::random(&mut rng);

        let metadata = BenchMetadata {
            operation: "rerandomize",
            iterations,
        };

        bench.benchmark::<(), ()>(metadata, &|| {
            for _ in 0..iterations {
                #[cfg(feature = "elgamal3")]
                let _ = rerandomize(&encrypted, &r);
                #[cfg(not(feature = "elgamal3"))]
                let _ = rerandomize(&encrypted, &public_key, &r);
            }
            Ok(())
        });
    }

    // Benchmark reshuffle
    {
        let (_, public_key) = setup_keys();
        let mut rng = rng();
        let message = GroupElement::random(&mut rng);
        let encrypted = encrypt(&message, &public_key, &mut rng);
        let s = ScalarNonZero::random(&mut rng);

        let metadata = BenchMetadata {
            operation: "reshuffle",
            iterations,
        };

        bench.benchmark::<(), ()>(metadata, &|| {
            for _ in 0..iterations {
                let _ = reshuffle(&encrypted, &s);
            }
            Ok(())
        });
    }

    // Benchmark rekey
    {
        let (_, public_key) = setup_keys();
        let mut rng = rng();
        let message = GroupElement::random(&mut rng);
        let encrypted = encrypt(&message, &public_key, &mut rng);
        let k = ScalarNonZero::random(&mut rng);

        let metadata = BenchMetadata {
            operation: "rekey",
            iterations,
        };

        bench.benchmark::<(), ()>(metadata, &|| {
            for _ in 0..iterations {
                let _ = rekey(&encrypted, &k);
            }
            Ok(())
        });
    }

    // Benchmark rsk
    {
        let (_, public_key) = setup_keys();
        let mut rng = rng();
        let message = GroupElement::random(&mut rng);
        let encrypted = encrypt(&message, &public_key, &mut rng);
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);

        let metadata = BenchMetadata {
            operation: "rsk",
            iterations,
        };

        bench.benchmark::<(), ()>(metadata, &|| {
            for _ in 0..iterations {
                let _ = rsk(&encrypted, &s, &k);
            }
            Ok(())
        });
    }

    // Benchmark rrsk
    {
        let (_, public_key) = setup_keys();
        let mut rng = rng();
        let message = GroupElement::random(&mut rng);
        let encrypted = encrypt(&message, &public_key, &mut rng);
        let r = ScalarNonZero::random(&mut rng);
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);

        let metadata = BenchMetadata {
            operation: "rrsk",
            iterations,
        };

        bench.benchmark::<(), ()>(metadata, &|| {
            for _ in 0..iterations {
                #[cfg(feature = "elgamal3")]
                let _ = rrsk(&encrypted, &r, &s, &k);
                #[cfg(not(feature = "elgamal3"))]
                let _ = rrsk(&encrypted, &public_key, &r, &s, &k);
            }
            Ok(())
        });
    }

    // Benchmark reshuffle2
    {
        let (_, public_key) = setup_keys();
        let mut rng = rng();
        let message = GroupElement::random(&mut rng);
        let encrypted = encrypt(&message, &public_key, &mut rng);
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);

        let metadata = BenchMetadata {
            operation: "reshuffle2",
            iterations,
        };

        bench.benchmark::<(), ()>(metadata, &|| {
            for _ in 0..iterations {
                let _ = reshuffle2(&encrypted, &s_from, &s_to);
            }
            Ok(())
        });
    }

    // Benchmark rekey2
    {
        let (_, public_key) = setup_keys();
        let mut rng = rng();
        let message = GroupElement::random(&mut rng);
        let encrypted = encrypt(&message, &public_key, &mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);

        let metadata = BenchMetadata {
            operation: "rekey2",
            iterations,
        };

        bench.benchmark::<(), ()>(metadata, &|| {
            for _ in 0..iterations {
                let _ = rekey2(&encrypted, &k_from, &k_to);
            }
            Ok(())
        });
    }

    // Benchmark rsk2
    {
        let (_, public_key) = setup_keys();
        let mut rng = rng();
        let message = GroupElement::random(&mut rng);
        let encrypted = encrypt(&message, &public_key, &mut rng);
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);

        let metadata = BenchMetadata {
            operation: "rsk2",
            iterations,
        };

        bench.benchmark::<(), ()>(metadata, &|| {
            for _ in 0..iterations {
                let _ = rsk2(&encrypted, &s_from, &s_to, &k_from, &k_to);
            }
            Ok(())
        });
    }

    // Benchmark rrsk2
    {
        let (_, public_key) = setup_keys();
        let mut rng = rng();
        let message = GroupElement::random(&mut rng);
        let encrypted = encrypt(&message, &public_key, &mut rng);
        let r = ScalarNonZero::random(&mut rng);
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);

        let metadata = BenchMetadata {
            operation: "rrsk2",
            iterations,
        };

        bench.benchmark::<(), ()>(metadata, &|| {
            for _ in 0..iterations {
                #[cfg(feature = "elgamal3")]
                let _ = rrsk2(&encrypted, &r, &s_from, &s_to, &k_from, &k_to);
                #[cfg(not(feature = "elgamal3"))]
                let _ = rrsk2(&encrypted, &public_key, &r, &s_from, &s_to, &k_from, &k_to);
            }
            Ok(())
        });
    }
}
