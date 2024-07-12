use rand_core::OsRng;
use libpep::high_level::*;

// #[test]
// fn test() {
//     let mut rng = OsRng;
//     let data = b"test data";
//     let pseudonym = new_random_pseudonym(&mut rng);
//
//     let (pk, sk) = generate_keys(&mut rng);
//     let encrypted_pseudonym = encrypt_pseudonym(&pseudonym, &pk, &mut rng);
//     let decrypted_pseudonym = decrypt_pseudonym(&encrypted_pseudonym, &sk);
//     assert_eq!(pseudonym, decrypted_pseudonym);
//     assert_eq!(pseudonym.to_bytes(), decrypted_pseudonym.to_bytes());
//
//     let data_point = DataPoint::from_bytes(data).unwrap();
//     let encrypted_data = encrypt_data(&data_point, &pk, &mut rng);
//     let decrypted_data = decrypt_data(&encrypted_data, &sk);
//     assert_eq!(data_point, decrypted_data);
//     println!("{:b}", data);
//     println!("{:v}", data_point.to_bytes());
//     println!("{:?}", decrypted_data.to_bytes());
//     assert_eq!(data, decrypted_data.to_bytes());
// }

