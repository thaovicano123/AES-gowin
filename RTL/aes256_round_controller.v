//==============================================================================
// File: aes256_round_controller.v
// Description: Round Controller FSM for AES-256
// - Controls 14 encryption/decryption rounds
// - Manages state transitions and round counter
// - Generates control signals for datapath
//==============================================================================

module aes256_round_controller (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start_i,       // Start encryption/decryption
    input  wire        mode_i,        // 0=Encrypt, 1=Decrypt
    input  wire        key_exp_done_i,// Key expansion complete
    output reg  [3:0]  round_num_o,   // Current round number (0-14)
    output reg         busy_o,        // Core is busy
    output reg         valid_o,       // Output is valid
    output reg         load_input_o,  // Load plaintext/ciphertext
    output reg         apply_subbytes_o,
    output reg         apply_shiftrows_o,
    output reg         apply_mixcolumns_o,
    output reg         apply_addroundkey_o
);

    //==========================================================================
    // FSM STATES
    //==========================================================================
    localparam [3:0] IDLE         = 4'b0000;
    localparam [3:0] WAIT_KEY     = 4'b0001;
    localparam [3:0] LOAD_DATA    = 4'b0010;
    localparam [3:0] ROUND_0      = 4'b0011;
    localparam [3:0] ROUND_1_13   = 4'b0100;
    localparam [3:0] ROUND_14     = 4'b0101;
    localparam [3:0] OUTPUT       = 4'b0110;

    reg [3:0] state, next_state;
    reg [3:0] round_count;

    //==========================================================================
    // STATE REGISTER
    //==========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
        end else begin
            state <= next_state;
        end
    end

    //==========================================================================
    // NEXT STATE LOGIC
    //==========================================================================
    always @(*) begin
        next_state = state;
        
        case (state)
            IDLE: begin
                if (start_i)
                    next_state = WAIT_KEY;
            end

            WAIT_KEY: begin
                if (key_exp_done_i)
                    next_state = LOAD_DATA;
            end

            LOAD_DATA: begin
                next_state = ROUND_0;
            end

            ROUND_0: begin
                next_state = ROUND_1_13;
            end

            ROUND_1_13: begin
                if (round_count >= 12)  // After round 13 (count=12), go to round 14
                    next_state = ROUND_14;
            end

            ROUND_14: begin
                next_state = OUTPUT;
            end

            OUTPUT: begin
                if (!start_i)
                    next_state = IDLE;
            end

            default: next_state = IDLE;
        endcase
    end

    //==========================================================================
    // ROUND COUNTER
    //==========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            round_count <= 4'd0;
        end else begin
            case (state)
                IDLE: begin
                    round_count <= 4'd0;
                end

                ROUND_0: begin
                    round_count <= 4'd0;
                end

                ROUND_1_13: begin
                    if (round_count < 13)
                        round_count <= round_count + 1'b1;
                end

                ROUND_14: begin
                    round_count <= 4'd14;
                end

                default: begin
                    round_count <= round_count;
                end
            endcase
        end
    end

    //==========================================================================
    // OUTPUT LOGIC (COMBINATIONAL for zero-delay control)
    //==========================================================================
    always @(*) begin
        // Default values
        busy_o = 1'b0;
        valid_o = 1'b0;
        load_input_o = 1'b0;
        apply_subbytes_o = 1'b0;
        apply_shiftrows_o = 1'b0;
        apply_mixcolumns_o = 1'b0;
        apply_addroundkey_o = 1'b0;
        round_num_o = 4'd0;

        case (state)
            IDLE: begin
                busy_o = 1'b0;
                valid_o = 1'b0;
                round_num_o = 4'd0;
            end

            WAIT_KEY: begin
                busy_o = 1'b1;
                valid_o = 1'b0;
            end

            LOAD_DATA: begin
                load_input_o = 1'b1;
                busy_o = 1'b1;
                valid_o = 1'b0;
            end

            ROUND_0: begin
                // Round 0: Only AddRoundKey
                apply_addroundkey_o = 1'b1;
                round_num_o = mode_i ? 4'd14 : 4'd0;  // Decrypt starts with key[14]
                busy_o = 1'b1;
                valid_o = 1'b0;
            end

            ROUND_1_13: begin
                // Rounds 1-13
                if (mode_i) begin
                    // Decryption order: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
                    apply_subbytes_o = 1'b1;
                    apply_shiftrows_o = 1'b1;
                    apply_addroundkey_o = 1'b1;
                    apply_mixcolumns_o = 1'b1;
                    round_num_o = 4'd13 - round_count;  // Keys: 13, 12, ..., 1 for rounds 1-13
                end else begin
                    // Encryption order: SubBytes → ShiftRows → MixColumns → AddRoundKey
                    apply_subbytes_o = 1'b1;
                    apply_shiftrows_o = 1'b1;
                    apply_mixcolumns_o = 1'b1;
                    apply_addroundkey_o = 1'b1;
                    round_num_o = round_count + 1;  // Keys: 1, 2, ..., 13 for rounds 1-13
                end
                busy_o = 1'b1;
                valid_o = 1'b0;
            end

            ROUND_14: begin
                // Final round: No MixColumns
                if (mode_i) begin
                    // Decryption: InvShiftRows → InvSubBytes → AddRoundKey
                    apply_shiftrows_o = 1'b1;
                    apply_subbytes_o = 1'b1;
                    apply_addroundkey_o = 1'b1;
                    round_num_o = 4'd0;  // Final decrypt uses key[0]
                end else begin
                    // Encryption: SubBytes → ShiftRows → AddRoundKey
                    apply_subbytes_o = 1'b1;
                    apply_shiftrows_o = 1'b1;
                    apply_addroundkey_o = 1'b1;
                    round_num_o = 4'd14;  // Final encrypt uses key[14]
                end
                busy_o = 1'b1;
                valid_o = 1'b0;
            end

            OUTPUT: begin
                busy_o = 1'b0;
                valid_o = 1'b1;
                round_num_o = 4'd0;
            end

            default: begin
                busy_o = 1'b0;
                valid_o = 1'b0;
                round_num_o = 4'd0;
            end
        endcase
    end

endmodule
