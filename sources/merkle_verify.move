module merkle_verify::merkle {
    use std::string::{Self as string};
    use std::vector;
    use std::hash;

    const InvalidProof: u64 = 2;
    const ERootMisMatched: u64 = 1;

    public fun verify_merkle(root:vector<u8>, leaf: vector<u8>, merkle_hashes: vector<vector<u8>>, merkle_directions: vector<vector<u8>>): vector<u8>{ 
        let merkle_length = vector::length(&merkle_hashes);
        let i = 0;
        let hash_data = leaf;
        let vec_tree = vector::empty<u8>();
        while (i < merkle_length) {
            let merkle_data = *vector::borrow(&merkle_hashes, i);
            let merkle_direction = *vector::borrow(&merkle_directions, i);
            if (string::utf8(merkle_direction) == string::utf8(b"left")){
                let merkle_data_left = merkle_data;
                vector::append(&mut vec_tree, merkle_data_left);
                vector::append(&mut vec_tree, hash_data);                
                hash_data = hash::sha2_256(vec_tree);
                vec_tree = vector::empty<u8>();
            } else if (string::utf8(merkle_direction) == string::utf8(b"right")) {
                vector::append(&mut vec_tree, hash_data );
                vector::append(&mut vec_tree, merkle_data );
                hash_data = hash::sha2_256(vec_tree);
                vec_tree = vector::empty<u8>();
            } else {
                InvalidProof;
            };
            i = i + 1;
        };
        assert!(root == hash_data, ERootMisMatched);
        hash_data
    }
}
