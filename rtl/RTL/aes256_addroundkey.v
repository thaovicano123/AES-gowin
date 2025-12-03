//==============================================================================
// File: aes256_addroundkey.v
// Description: AddRoundKey Transformation for AES-256
// - XOR state with round key
// - Same operation for both encryption and decryption
// - Combinational logic (no registers)
//==============================================================================

module aes256_addroundkey (
    input  wire [127:0] state_i,     // Input state (16 bytes)
    input  wire [127:0] round_key_i, // Round key (16 bytes)
    output wire [127:0] state_o      // Output state (16 bytes)
);

    //==========================================================================
    // ADDROUNDKEY TRANSFORMATION
    // Simple XOR operation: state XOR round_key
    //==========================================================================
    assign state_o = state_i ^ round_key_i;

endmodule
