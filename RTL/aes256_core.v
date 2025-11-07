//==============================================================================
// File: aes256_core.v
// Description: Top-Level AES-256 Encryption/Decryption Core
// - Complete AES-256 implementation with encryption and decryption
// - Compliant with FIPS-197 standard
// - Optimized for FPGA implementation (60k LUTs target)
//==============================================================================
// Target: 100 MHz, <500mW, <10kB RAM
// Interface: 9 ports (6 inputs + 3 outputs)
// Latency: 18 clock cycles (deterministic)
//==============================================================================

module aes256_core (
    // Clock and Reset
    input  wire         clk,            // System clock (100 MHz)
    input  wire         rst_n,          // Active-low reset
    
    // Control Inputs
    input  wire         start_i,        // Start encryption/decryption
    input  wire         mode_i,         // 0=Encrypt, 1=Decrypt
    
    // Data Inputs
    input  wire [127:0] plaintext_i,    // Input data (plaintext or ciphertext)
    input  wire [255:0] key_i,          // 256-bit master key
    
    // Outputs
    output wire [127:0] ciphertext_o,   // Output data (ciphertext or plaintext)
    output wire         valid_o,        // Output valid flag
    output wire         busy_o          // Core busy flag
);

    //==========================================================================
    // INTERNAL SIGNALS
    //==========================================================================
    
    // Key Expansion signals (combinational - no done signal needed)
    wire [127:0] round_keys [0:14];     // 15 round keys
    
    // Round Controller signals
    wire [3:0] round_num;
    wire load_input;
    wire apply_subbytes;
    wire apply_shiftrows;
    wire apply_mixcolumns;
    wire apply_addroundkey;
    
    // State register
    reg [127:0] state_reg;
    
    // Transformation outputs
    wire [127:0] subbytes_out;
    wire [127:0] shiftrows_out;
    wire [127:0] mixcolumns_out;
    wire [127:0] addroundkey_out;
    
    // Round key signals
    wire [127:0] current_round_key_raw;
    wire [127:0] current_round_key;
    wire [127:0] inv_mc_round_key;

    //==========================================================================
    // KEY EXPANSION MODULE (COMBINATIONAL)
    //==========================================================================
    aes256_key_expansion_comb key_exp_inst (
        .key_i(key_i),
        .round_keys_o(round_keys)
    );

    //==========================================================================
    // ROUND CONTROLLER (FSM)
    //==========================================================================
    aes256_round_controller round_ctrl_inst (
        .clk(clk),
        .rst_n(rst_n),
        .start_i(start_i),
        .mode_i(mode_i),
        .key_exp_done_i(1'b1),  // Always ready with combinational key expansion
        .round_num_o(round_num),
        .busy_o(busy_o),
        .valid_o(valid_o),
        .load_input_o(load_input),
        .apply_subbytes_o(apply_subbytes),
        .apply_shiftrows_o(apply_shiftrows),
        .apply_mixcolumns_o(apply_mixcolumns),
        .apply_addroundkey_o(apply_addroundkey)
    );

    //==========================================================================
    // TRANSFORMATION MODULES
    //==========================================================================
    
    // SubBytes / InvSubBytes
    aes256_subbytes subbytes_inst (
        .mode_i(mode_i),
        .state_i(state_reg),
        .state_o(subbytes_out)
    );

    // ShiftRows / InvShiftRows
    aes256_shiftrows shiftrows_inst (
        .mode_i(mode_i),
        .state_i(subbytes_out),
        .state_o(shiftrows_out)
    );

    // MixColumns / InvMixColumns
    aes256_mixcolumns mixcolumns_inst (
        .mode_i(mode_i),
        .state_i(shiftrows_out),
        .state_o(mixcolumns_out)
    );

    // AddRoundKey - for Equivalent Inverse Cipher, need to apply InvMixColumns to round keys
    assign current_round_key_raw = round_keys[round_num];
    
    // For decryption middle rounds (1-13), apply InvMixColumns to round key
    aes256_mixcolumns inv_mc_key_inst (
        .mode_i(1'b1),  // InvMixColumns
        .state_i(current_round_key_raw),
        .state_o(inv_mc_round_key)
    );
    
    // Use transformed key for decrypt middle rounds, original key otherwise
    assign current_round_key = (mode_i && apply_mixcolumns) ? inv_mc_round_key : current_round_key_raw;
    
    wire [127:0] addroundkey_in;
    assign addroundkey_in = apply_mixcolumns ? mixcolumns_out :
                           apply_shiftrows ? shiftrows_out :
                           apply_subbytes ? subbytes_out :
                           state_reg;
    
    aes256_addroundkey addroundkey_inst (
        .state_i(addroundkey_in),
        .round_key_i(current_round_key),
        .state_o(addroundkey_out)
    );

    //==========================================================================
    // STATE REGISTER UPDATE
    //==========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_reg <= 128'd0;
        end else begin
            // Load input data
            if (load_input) begin
                state_reg <= plaintext_i;
            end
            // Update state with transformation results
            else if (apply_addroundkey) begin
                state_reg <= addroundkey_out;
            end
        end
    end

    //==========================================================================
    // OUTPUT ASSIGNMENT
    //==========================================================================
    assign ciphertext_o = state_reg;

endmodule
