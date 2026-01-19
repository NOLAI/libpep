mod distributed;

use distributed::*;
use energy_bench::EnergyBenchBuilder;

struct BenchMetadata {
    operation: &'static str,
    num_servers: usize,
    num_entities: usize,
    num_pseudonyms_per_entity: usize,
    num_attributes_per_entity: usize,
}

impl energy_bench::Metadata<5> for BenchMetadata {
    fn get_header() -> [&'static str; 5] {
        ["Operation", "Servers", "Entities", "Pseudonyms/Entity", "Attributes/Entity"]
    }

    fn get_values(&self) -> [String; 5] {
        [
            self.operation.to_string(),
            self.num_servers.to_string(),
            self.num_entities.to_string(),
            self.num_pseudonyms_per_entity.to_string(),
            self.num_attributes_per_entity.to_string(),
        ]
    }
}

fn main() {
    let mut builder = EnergyBenchBuilder::new("libpep_distributed_operations");
    builder.set_number_of_runs(10);
    let mut bench = builder.build();

    // Benchmark distributed transcrypt with individual operations
    for num_servers in BENCHMARK_SERVERS {
        for num_entities in BENCHMARK_ENTITIES {
            for (num_pseudonyms_per_entity, num_attributes_per_entity) in BENCHMARK_STRUCTURES {
                let (systems, client_a, _, session_a, session_b, domain_a, domain_b) =
                    setup_distributed_system(num_servers);

                // Pre-generate all data as entity tuples
                let entities = generate_entities(num_entities, num_pseudonyms_per_entity, num_attributes_per_entity, &client_a);

                let metadata = BenchMetadata {
                    operation: "distributed_transcrypt",
                    num_servers,
                    num_entities,
                    num_pseudonyms_per_entity,
                    num_attributes_per_entity,
                };

                bench.benchmark::<(), ()>(metadata, &|| {
                    process_entities_individually(&entities, &systems, &domain_a, &domain_b, &session_a, &session_b);
                    Ok(())
                });
            }
        }
    }

    // Benchmark distributed transcrypt with batch operations
    for num_servers in BENCHMARK_SERVERS {
        for num_entities in BENCHMARK_ENTITIES {
            for (num_pseudonyms_per_entity, num_attributes_per_entity) in BENCHMARK_STRUCTURES {
                let (systems, client_a, _, session_a, session_b, domain_a, domain_b) =
                    setup_distributed_system(num_servers);

                // Pre-generate all data as EncryptedData tuples
                let encrypted_data = generate_entities(num_entities, num_pseudonyms_per_entity, num_attributes_per_entity, &client_a);

                let metadata = BenchMetadata {
                    operation: "distributed_transcrypt_batch",
                    num_servers,
                    num_entities,
                    num_pseudonyms_per_entity,
                    num_attributes_per_entity,
                };

                bench.benchmark::<(), ()>(metadata, &|| {
                    process_entities_batch(encrypted_data.clone(), &systems, &domain_a, &domain_b, &session_a, &session_b);
                    Ok(())
                });
            }
        }
    }
}