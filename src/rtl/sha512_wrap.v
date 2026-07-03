/* This module computes H(k), H(hM) or H(R,A,M), only 256 bit M are supported */

module sha512_wrap (
    input wire clk,
    input wire rst,

    input wire hw_ena,

    output wire hw_ready,
    output wire hw_error,
    output wire hw_digest_valid,
    output wire [511:0] hw_digest,

    input wire [1:0] hw_mode,
    /* Mode 1, H(sk); hash the secret key */
    input wire [255:0] hw_sk,
    /* Mode 2, H(h_b,...,h_{2b-1},M); hash the randomizer and the message. */
    input wire [255:0] hw_h,
    /* Mode 3, H(R,A,M); Bind R, the compressed point. A, the public key. And M,
    * the message. */
    input wire [255:0] hw_R,
    input wire [255:0] hw_A,
    /* The message for mode 2 & 3; 256 bits. */
    input wire [255:0] hw_M
    );


/*---------------------------INTERNAL CONSTANTS-------------------------------*/

/*  The hash always fits in one block. */
localparam STATE_IDLE = 0;
localparam STATE_INIT = 1;
localparam STATE_BUSY = 2;

/*------------------------------------REGS------------------------------------*/
reg [1023:0] sha_block_reg;
reg [1023:0] sha_block_new;

reg ready_flag;
reg error_flag;

reg [1:0] hash_wrap_state_reg;
reg [1:0] hash_wrap_state_new;

reg sha_init;
reg sha_next;

reg hw_comp_done;
/*------------------------------------WIRES-----------------------------------*/

wire [1:0] sha_mode;
wire [1023:0] sha_block;
wire sha_ready;
wire [511:0] sha_digest;
wire sha_digest_valid;

/*--------------------------------COMPONENTS----------------------------------*/

sha512_core sha512 (
    .clk(clk),
    .reset_n(!rst),
    .init(sha_init),
    .next(sha_next),
    .mode(sha_mode),
    /* .work_factor(work_factor), */
    /* .work_factor_num(work_factor_num), */
    .block(sha_block),
    .ready(sha_ready),
    /* .state_wr_data(state_wr_data), */
    .digest(sha_digest),
    .digest_valid(sha_digest_valid)
    );
/*---------------------------------CONNECTIVITY-------------------------------*/

assign hw_ready = ready_flag;
assign hw_error = error_flag;
assign sha_block = sha_block_reg;

assign sha_mode = 3;  // Always SHA-512
assign hw_digest = sha_digest;
assign hw_digest_valid = hw_comp_done;

/*-------------------------------------FSM------------------------------------*/

/* Synchronous state update */
always @(posedge clk) begin
    if (rst) begin
        hash_wrap_state_reg <= STATE_IDLE;
        sha_block_reg <= 1024'b0;
    end
    else begin
        hash_wrap_state_reg <= hash_wrap_state_new;
        sha_block_reg <= sha_block_new;
    end
end

/* Asynchronous next state logic */
always @* begin
    hash_wrap_state_new = STATE_IDLE;

    ready_flag = 0;
    error_flag = 0;

    sha_init = 0;
    sha_next = 0;
    sha_block_new = sha_block_reg;
    hw_comp_done = 1'b0;

    case (hash_wrap_state_reg)
        STATE_IDLE:
            begin
                ready_flag = 1;

                if (hw_ena & sha_ready) begin
                    hash_wrap_state_new = STATE_INIT;
                end
                else if (hw_ena) begin
                    error_flag = 1;
                end
            end
        STATE_INIT:
            begin
                hash_wrap_state_new = STATE_BUSY;
                sha_init = 1;
            end
        STATE_BUSY:
            begin
                hash_wrap_state_new = STATE_BUSY;
                if (sha_digest_valid) begin
                    hw_comp_done = 1'b1;
                    hash_wrap_state_new = STATE_IDLE;
                end
            end
    endcase

    /* A hash will be one block, either 256, 384 or 768 bits.
    * This also preforms the required input padding. */
    case (hw_mode)
        // H(k)
        0 : sha_block_new = {hw_sk, 1'b1, 639'b0, 128'd256};
        // H(hM)
        1 : sha_block_new = {hw_h, hw_M, 1'b1, 383'b0, 128'd512};
        // H(R,A,M)
        2 : sha_block_new = {hw_R, hw_A, hw_M, 1'b1, 127'b0, 128'd768};
        3 :
            begin
                error_flag = 1;
                hash_wrap_state_new = STATE_IDLE;
            end
    endcase
end

endmodule


//======================================================================
//
// sha512_core.v
// -------------
// Verilog 2001 implementation of the SHA-512 hash function.
// This is the internal core with wide interfaces.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2014, NORDUnet A/S
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// - Redistributions of source code must retain the above copyright notice,
//   this list of conditions and the following disclaimer.
//
// - Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// - Neither the name of the NORDUnet nor the names of its contributors may
//   be used to endorse or promote products derived from this software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module sha512_core(
                   input wire            clk,
                   input wire            reset_n,

                   input wire            init,
                   input wire            next,
                   input wire [1 : 0]    mode,

                   input wire            work_factor,
                   input wire [31 : 0]   work_factor_num,

                   input wire [1023 : 0] block,

                   output wire           ready,

                   input wire [31 : 0]   state_wr_data,
                   input wire            state00_we,
                   input wire            state01_we,
                   input wire            state02_we,
                   input wire            state03_we,
                   input wire            state04_we,
                   input wire            state05_we,
                   input wire            state06_we,
                   input wire            state07_we,
                   input wire            state08_we,
                   input wire            state09_we,
                   input wire            state10_we,
                   input wire            state11_we,
                   input wire            state12_we,
                   input wire            state13_we,
                   input wire            state14_we,
                   input wire            state15_we,

                   output wire [511 : 0] digest,
                   output wire           digest_valid
                  );


  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter SHA512_ROUNDS = 79;

  parameter CTRL_IDLE   = 0;
  parameter CTRL_ROUNDS = 1;
  parameter CTRL_DONE   = 2;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [63 : 0] a_reg;
  reg [63 : 0] a_new;
  reg [63 : 0] b_reg;
  reg [63 : 0] b_new;
  reg [63 : 0] c_reg;
  reg [63 : 0] c_new;
  reg [63 : 0] d_reg;
  reg [63 : 0] d_new;
  reg [63 : 0] e_reg;
  reg [63 : 0] e_new;
  reg [63 : 0] f_reg;
  reg [63 : 0] f_new;
  reg [63 : 0] g_reg;
  reg [63 : 0] g_new;
  reg [63 : 0] h_reg;
  reg [63 : 0] h_new;
  reg          a_h_we;

  reg [63 : 0] H0_reg;
  reg [63 : 0] H0_new;
  reg [63 : 0] H1_reg;
  reg [63 : 0] H1_new;
  reg [63 : 0] H2_reg;
  reg [63 : 0] H2_new;
  reg [63 : 0] H3_reg;
  reg [63 : 0] H3_new;
  reg [63 : 0] H4_reg;
  reg [63 : 0] H4_new;
  reg [63 : 0] H5_reg;
  reg [63 : 0] H5_new;
  reg [63 : 0] H6_reg;
  reg [63 : 0] H6_new;
  reg [63 : 0] H7_reg;
  reg [63 : 0] H7_new;
  reg          H_we;

  reg [6 : 0] t_ctr_reg;
  reg [6 : 0] t_ctr_new;
  reg         t_ctr_we;
  reg         t_ctr_inc;
  reg         t_ctr_rst;

  reg [31 : 0] work_factor_ctr_reg;
  reg [31 : 0] work_factor_ctr_new;
  reg          work_factor_ctr_rst;
  reg          work_factor_ctr_inc;
  reg          work_factor_ctr_done;
  reg          work_factor_ctr_we;

  reg digest_valid_reg;
  reg digest_valid_new;
  reg digest_valid_we;

  reg [1 : 0] sha512_ctrl_reg;
  reg [1 : 0] sha512_ctrl_new;
  reg         sha512_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg digest_init;
  reg digest_update;

  reg state_init;
  reg state_update;

  reg first_block;

  reg ready_flag;

  reg [63 : 0] t1;
  reg [63 : 0] t2;

  wire [63 : 0] k_data;

  reg           w_init;
  reg           w_next;
  wire [63 : 0] w_data;

  wire [63 : 0] H0_0;
  wire [63 : 0] H0_1;
  wire [63 : 0] H0_2;
  wire [63 : 0] H0_3;
  wire [63 : 0] H0_4;
  wire [63 : 0] H0_5;
  wire [63 : 0] H0_6;
  wire [63 : 0] H0_7;


  //----------------------------------------------------------------
  // Module instantiantions.
  //----------------------------------------------------------------
  sha512_k_constants k_constants_inst(
                                      .addr(t_ctr_reg),
                                      .K(k_data)
                                     );


  sha512_h_constants h_constants_inst(
                                      .mode(mode),

                                      .H0(H0_0),
                                      .H1(H0_1),
                                      .H2(H0_2),
                                      .H3(H0_3),
                                      .H4(H0_4),
                                      .H5(H0_5),
                                      .H6(H0_6),
                                      .H7(H0_7)
                                     );


  sha512_w_mem w_mem_inst(
                          .clk(clk),
                          .reset_n(reset_n),

                          .block(block),

                          .init(w_init),
                          .next(w_next),
                          .w(w_data)
                         );


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign ready = ready_flag;

  assign digest = {H0_reg, H1_reg, H2_reg, H3_reg,
                   H4_reg, H5_reg, H6_reg, H7_reg};

  assign digest_valid = digest_valid_reg;


  //----------------------------------------------------------------
  // reg_update
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin : reg_update
      if (!reset_n)
        begin
          a_reg               <= 64'h0000000000000000;
          b_reg               <= 64'h0000000000000000;
          c_reg               <= 64'h0000000000000000;
          d_reg               <= 64'h0000000000000000;
          e_reg               <= 64'h0000000000000000;
          f_reg               <= 64'h0000000000000000;
          g_reg               <= 64'h0000000000000000;
          h_reg               <= 64'h0000000000000000;
          H0_reg              <= 64'h0000000000000000;
          H1_reg              <= 64'h0000000000000000;
          H2_reg              <= 64'h0000000000000000;
          H3_reg              <= 64'h0000000000000000;
          H4_reg              <= 64'h0000000000000000;
          H5_reg              <= 64'h0000000000000000;
          H6_reg              <= 64'h0000000000000000;
          H7_reg              <= 64'h0000000000000000;
          work_factor_ctr_reg <= 32'h00000000;
          digest_valid_reg    <= 0;
          t_ctr_reg           <= 7'h00;
          sha512_ctrl_reg     <= CTRL_IDLE;
        end
      else
        begin

          if (a_h_we)
            begin
              a_reg <= a_new;
              b_reg <= b_new;
              c_reg <= c_new;
              d_reg <= d_new;
              e_reg <= e_new;
              f_reg <= f_new;
              g_reg <= g_new;
              h_reg <= h_new;
            end

          if (H_we)
            begin
              H0_reg <= H0_new;
              H1_reg <= H1_new;
              H2_reg <= H2_new;
              H3_reg <= H3_new;
              H4_reg <= H4_new;
              H5_reg <= H5_new;
              H6_reg <= H6_new;
              H7_reg <= H7_new;
            end

          if (state00_we)
            H0_reg <= {state_wr_data, H0_reg[31 : 0]};

          if (state01_we)
            H0_reg <= {H0_reg[63 : 32], state_wr_data};

          if (state02_we)
            H1_reg <= {state_wr_data, H1_reg[31 : 0]};

          if (state03_we)
            H1_reg <= {H1_reg[63 : 32], state_wr_data};

          if (state04_we)
            H2_reg <= {state_wr_data, H2_reg[31 : 0]};

          if (state05_we)
            H2_reg <= {H2_reg[63 : 32], state_wr_data};

          if (state06_we)
            H3_reg <= {state_wr_data, H3_reg[31 : 0]};

          if (state07_we)
            H3_reg <= {H3_reg[63 : 32], state_wr_data};

          if (state08_we)
            H4_reg <= {state_wr_data, H4_reg[31 : 0]};

          if (state09_we)
            H4_reg <= {H4_reg[63 : 32], state_wr_data};

          if (state10_we)
            H5_reg <= {state_wr_data, H5_reg[31 : 0]};

          if (state11_we)
            H5_reg <= {H5_reg[63 : 32], state_wr_data};

          if (state12_we)
            H6_reg <= {state_wr_data, H6_reg[31 : 0]};

          if (state13_we)
            H6_reg <= {H6_reg[63 : 32], state_wr_data};

          if (state14_we)
            H7_reg <= {state_wr_data, H7_reg[31 : 0]};

          if (state15_we)
            H7_reg <= {H7_reg[63 : 32], state_wr_data};

          if (t_ctr_we)
            begin
              t_ctr_reg <= t_ctr_new;
            end

          if (work_factor_ctr_we)
            begin
              work_factor_ctr_reg <= work_factor_ctr_new;
            end

          if (digest_valid_we)
            begin
              digest_valid_reg <= digest_valid_new;
            end

          if (sha512_ctrl_we)
            begin
              sha512_ctrl_reg <= sha512_ctrl_new;
            end
        end
    end // reg_update


  //----------------------------------------------------------------
  // digest_logic
  //
  // The logic needed to init as well as update the digest.
  //----------------------------------------------------------------
  always @*
    begin : digest_logic
      H0_new = 64'h00000000;
      H1_new = 64'h00000000;
      H2_new = 64'h00000000;
      H3_new = 64'h00000000;
      H4_new = 64'h00000000;
      H5_new = 64'h00000000;
      H6_new = 64'h00000000;
      H7_new = 64'h00000000;
      H_we = 0;

      if (digest_init)
        begin
          H0_new = H0_0;
          H1_new = H0_1;
          H2_new = H0_2;
          H3_new = H0_3;
          H4_new = H0_4;
          H5_new = H0_5;
          H6_new = H0_6;
          H7_new = H0_7;
          H_we = 1;
        end

      if (digest_update)
        begin
          H0_new = H0_reg + a_reg;
          H1_new = H1_reg + b_reg;
          H2_new = H2_reg + c_reg;
          H3_new = H3_reg + d_reg;
          H4_new = H4_reg + e_reg;
          H5_new = H5_reg + f_reg;
          H6_new = H6_reg + g_reg;
          H7_new = H7_reg + h_reg;
          H_we = 1;
        end
    end // digest_logic


  //----------------------------------------------------------------
  // t1_logic
  //
  // The logic for the T1 function.
  //----------------------------------------------------------------
  always @*
    begin : t1_logic
      reg [63 : 0] sum1;
      reg [63 : 0] ch;

      sum1 = {e_reg[13 : 0], e_reg[63 : 14]} ^
             {e_reg[17 : 0], e_reg[63 : 18]} ^
             {e_reg[40 : 0], e_reg[63 : 41]};

      ch = (e_reg & f_reg) ^ ((~e_reg) & g_reg);

      t1 = h_reg + sum1 + ch + k_data + w_data;
    end // t1_logic


  //----------------------------------------------------------------
  // t2_logic
  //
  // The logic for the T2 function
  //----------------------------------------------------------------
  always @*
    begin : t2_logic
      reg [63 : 0] sum0;
      reg [63 : 0] maj;

      sum0 = {a_reg[27 : 0], a_reg[63 : 28]} ^
             {a_reg[33 : 0], a_reg[63 : 34]} ^
             {a_reg[38 : 0], a_reg[63 : 39]};

      maj = (a_reg & b_reg) ^ (a_reg & c_reg) ^ (b_reg & c_reg);

      t2 = sum0 + maj;
    end // t2_logic


  //----------------------------------------------------------------
  // state_logic
  //
  // The logic needed to init as well as update the state during
  // round processing.
  //----------------------------------------------------------------
  always @*
    begin : state_logic
      a_new  = 64'h00000000;
      b_new  = 64'h00000000;
      c_new  = 64'h00000000;
      d_new  = 64'h00000000;
      e_new  = 64'h00000000;
      f_new  = 64'h00000000;
      g_new  = 64'h00000000;
      h_new  = 64'h00000000;
      a_h_we = 0;

      if (state_init)
        begin
          if (first_block)
            begin
              a_new  = H0_0;
              b_new  = H0_1;
              c_new  = H0_2;
              d_new  = H0_3;
              e_new  = H0_4;
              f_new  = H0_5;
              g_new  = H0_6;
              h_new  = H0_7;
              a_h_we = 1;
            end
          else
            begin
              a_new  = H0_reg;
              b_new  = H1_reg;
              c_new  = H2_reg;
              d_new  = H3_reg;
              e_new  = H4_reg;
              f_new  = H5_reg;
              g_new  = H6_reg;
              h_new  = H7_reg;
              a_h_we = 1;
            end
        end

      if (state_update)
        begin
          a_new  = t1 + t2;
          b_new  = a_reg;
          c_new  = b_reg;
          d_new  = c_reg;
          e_new  = d_reg + t1;
          f_new  = e_reg;
          g_new  = f_reg;
          h_new  = g_reg;
          a_h_we = 1;
        end
    end // state_logic


  //----------------------------------------------------------------
  // t_ctr
  //
  // Update logic for the round counter, a monotonically
  // increasing counter with reset.
  //----------------------------------------------------------------
  always @*
    begin : t_ctr
      t_ctr_new = 7'h00;
      t_ctr_we  = 0;

      if (t_ctr_rst)
        begin
          t_ctr_new = 7'h00;
          t_ctr_we  = 1;
        end

      if (t_ctr_inc)
        begin
          t_ctr_new = t_ctr_reg + 1'b1;
          t_ctr_we  = 1;
        end
    end // t_ctr


  //----------------------------------------------------------------
  // work_factor_ctr
  //
  // Work factor counter logic.
  //----------------------------------------------------------------
  always @*
    begin : work_factor_ctr
      work_factor_ctr_new  = 32'h00000000;
      work_factor_ctr_we   = 0;
      work_factor_ctr_done = 0;

      if (work_factor_ctr_reg == work_factor_num)
        begin
          work_factor_ctr_done = 1;
        end

      if (work_factor_ctr_rst)
        begin
          work_factor_ctr_new  = 32'h00000000;
          work_factor_ctr_we   = 1;
        end

      if (work_factor_ctr_inc)
        begin
          work_factor_ctr_new  = work_factor_ctr_reg + 1'b1;
          work_factor_ctr_we   = 1;
        end
    end // work_factor_ctr


  //----------------------------------------------------------------
  // sha512_ctrl_fsm
  //
  // Logic for the state machine controlling the core behaviour.
  //----------------------------------------------------------------
  always @*
    begin : sha512_ctrl_fsm
      digest_init         = 0;
      digest_update       = 0;

      state_init          = 0;
      state_update        = 0;

      first_block         = 0;
      ready_flag          = 0;

      w_init              = 0;
      w_next              = 0;

      t_ctr_inc           = 0;
      t_ctr_rst           = 0;

      digest_valid_new    = 0;
      digest_valid_we     = 0;

      work_factor_ctr_rst = 0;
      work_factor_ctr_inc = 0;

      sha512_ctrl_new     = CTRL_IDLE;
      sha512_ctrl_we      = 0;


      case (sha512_ctrl_reg)
        CTRL_IDLE:
          begin
            ready_flag = 1;

            if (init)
              begin
                work_factor_ctr_rst = 1;
                digest_init         = 1;
                w_init              = 1;
                state_init          = 1;
                first_block         = 1;
                t_ctr_rst           = 1;
                digest_valid_new    = 0;
                digest_valid_we     = 1;
                sha512_ctrl_new     = CTRL_ROUNDS;
                sha512_ctrl_we      = 1;
              end

            if (next)
              begin
                work_factor_ctr_rst = 1;
                w_init              = 1;
                state_init          = 1;
                t_ctr_rst           = 1;
                digest_valid_new    = 0;
                digest_valid_we     = 1;
                sha512_ctrl_new     = CTRL_ROUNDS;
                sha512_ctrl_we      = 1;
              end
          end


        CTRL_ROUNDS:
          begin
            w_next       = 1;
            state_update = 1;
            t_ctr_inc    = 1;

            if (t_ctr_reg == SHA512_ROUNDS)
              begin
                work_factor_ctr_inc = 1;
                sha512_ctrl_new     = CTRL_DONE;
                sha512_ctrl_we      = 1;
              end
          end


        CTRL_DONE:
          begin
            if (work_factor)
              begin
                if (!work_factor_ctr_done)
                  begin
                    w_init              = 1;
                    state_init          = 1;
                    t_ctr_rst           = 1;
                    sha512_ctrl_new     = CTRL_ROUNDS;
                    sha512_ctrl_we      = 1;
                  end
                else
                  begin
                    digest_update    = 1;
                    digest_valid_new = 1;
                    digest_valid_we  = 1;
                    sha512_ctrl_new  = CTRL_IDLE;
                    sha512_ctrl_we   = 1;
                  end
              end
            else
              begin
                digest_update    = 1;
                digest_valid_new = 1;
                digest_valid_we  = 1;
                sha512_ctrl_new  = CTRL_IDLE;
                sha512_ctrl_we   = 1;
              end
          end
      endcase // case (sha512_ctrl_reg)
    end // sha512_ctrl_fsm

endmodule // sha512_core

//======================================================================
// EOF sha512_core.v
//======================================================================


//======================================================================
//
// sha512_h_constants.v
// ---------------------
// The H initial constants for the different modes in SHA-512.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2014, NORDUnet A/S
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// - Redistributions of source code must retain the above copyright notice,
//   this list of conditions and the following disclaimer.
//
// - Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// - Neither the name of the NORDUnet nor the names of its contributors may
//   be used to endorse or promote products derived from this software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module sha512_h_constants(
                          input wire  [1 : 0]  mode,

                          output wire [63 : 0] H0,
                          output wire [63 : 0] H1,
                          output wire [63 : 0] H2,
                          output wire [63 : 0] H3,
                          output wire [63 : 0] H4,
                          output wire [63 : 0] H5,
                          output wire [63 : 0] H6,
                          output wire [63 : 0] H7
                         );

  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [63 : 0] tmp_H0;
  reg [63 : 0] tmp_H1;
  reg [63 : 0] tmp_H2;
  reg [63 : 0] tmp_H3;
  reg [63 : 0] tmp_H4;
  reg [63 : 0] tmp_H5;
  reg [63 : 0] tmp_H6;
  reg [63 : 0] tmp_H7;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign H0 = tmp_H0;
  assign H1 = tmp_H1;
  assign H2 = tmp_H2;
  assign H3 = tmp_H3;
  assign H4 = tmp_H4;
  assign H5 = tmp_H5;
  assign H6 = tmp_H6;
  assign H7 = tmp_H7;

  
  //----------------------------------------------------------------
  // mode_mux
  //
  // Based on the given mode, the correct H constants are selected.
  //----------------------------------------------------------------
  always @*
    begin : mode_mux
      case(mode)
        0:
          begin
            // SHA-512/224
            tmp_H0 = 64'h8c3d37c819544da2;
            tmp_H1 = 64'h73e1996689dcd4d6;
            tmp_H2 = 64'h1dfab7ae32ff9c82;
            tmp_H3 = 64'h679dd514582f9fcf;
            tmp_H4 = 64'h0f6d2b697bd44da8;
            tmp_H5 = 64'h77e36f7304c48942;
            tmp_H6 = 64'h3f9d85a86a1d36c8;
            tmp_H7 = 64'h1112e6ad91d692a1;
          end

        1:
          begin
            // SHA-512/256
            tmp_H0 = 64'h22312194fc2bf72c; 
            tmp_H1 = 64'h9f555fa3c84c64c2; 
            tmp_H2 = 64'h2393b86b6f53b151; 
            tmp_H3 = 64'h963877195940eabd; 
            tmp_H4 = 64'h96283ee2a88effe3; 
            tmp_H5 = 64'hbe5e1e2553863992; 
            tmp_H6 = 64'h2b0199fc2c85b8aa; 
            tmp_H7 = 64'h0eb72ddc81c52ca2;
          end
        
        2:
          begin
            // SHA-384
            tmp_H0 = 64'hcbbb9d5dc1059ed8;
            tmp_H1 = 64'h629a292a367cd507;
            tmp_H2 = 64'h9159015a3070dd17; 
            tmp_H3 = 64'h152fecd8f70e5939; 
            tmp_H4 = 64'h67332667ffc00b31; 
            tmp_H5 = 64'h8eb44a8768581511; 
            tmp_H6 = 64'hdb0c2e0d64f98fa7; 
            tmp_H7 = 64'h47b5481dbefa4fa4;
          end
        
        3:
          begin
            // SHA-512
            tmp_H0 = 64'h6a09e667f3bcc908;
            tmp_H1 = 64'hbb67ae8584caa73b;
            tmp_H2 = 64'h3c6ef372fe94f82b; 
            tmp_H3 = 64'ha54ff53a5f1d36f1; 
            tmp_H4 = 64'h510e527fade682d1; 
            tmp_H5 = 64'h9b05688c2b3e6c1f; 
            tmp_H6 = 64'h1f83d9abfb41bd6b; 
            tmp_H7 = 64'h5be0cd19137e2179;  
          end
      endcase // case (addr)
    end // block: mode_mux
endmodule // sha512_h_constants

//======================================================================
// sha512_h_constants.v
//======================================================================


//======================================================================
//
// sha512_k_constants.v
// --------------------
// The table K with constants in the SHA-512 hash function.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2014, NORDUnet A/S
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// - Redistributions of source code must retain the above copyright notice,
//   this list of conditions and the following disclaimer.
//
// - Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// - Neither the name of the NORDUnet nor the names of its contributors may
//   be used to endorse or promote products derived from this software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module sha512_k_constants(
                          input wire  [6 : 0]  addr,
                          output wire [63 : 0] K
                         );

  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [63 : 0] tmp_K;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign K = tmp_K;
  
  
  //----------------------------------------------------------------
  // addr_mux
  //----------------------------------------------------------------
  always @*
    begin : addr_mux
      case(addr)
        0:
          begin
            tmp_K = 64'h428a2f98d728ae22;
          end
        
        1:
          begin
            tmp_K = 64'h7137449123ef65cd;
          end

        2:
          begin
            tmp_K = 64'hb5c0fbcfec4d3b2f;
          end

        3:
          begin
            tmp_K = 64'he9b5dba58189dbbc;
          end

        4:
          begin
            tmp_K = 64'h3956c25bf348b538;
          end

        5:
          begin
            tmp_K = 64'h59f111f1b605d019;
          end

        6:
          begin
            tmp_K = 64'h923f82a4af194f9b;
          end

        7:
          begin
            tmp_K = 64'hab1c5ed5da6d8118;
          end

        8:
          begin
            tmp_K = 64'hd807aa98a3030242;
          end

        9:
          begin
            tmp_K = 64'h12835b0145706fbe;
          end

        10:
          begin
            tmp_K = 64'h243185be4ee4b28c;
          end

        11:
          begin
            tmp_K = 64'h550c7dc3d5ffb4e2;
          end

        12:
          begin
            tmp_K = 64'h72be5d74f27b896f;
          end

        13:
          begin
            tmp_K = 64'h80deb1fe3b1696b1;
          end

        14:
          begin
            tmp_K = 64'h9bdc06a725c71235;
          end
        
        15:
          begin
            tmp_K = 64'hc19bf174cf692694;
          end
        
        16:
          begin
            tmp_K = 64'he49b69c19ef14ad2;
          end

        17:
          begin
            tmp_K = 64'hefbe4786384f25e3;
          end

        18:
          begin
            tmp_K = 64'h0fc19dc68b8cd5b5;
          end
        
        19:
          begin
            tmp_K = 64'h240ca1cc77ac9c65;
          end
        
        20:
          begin
            tmp_K = 64'h2de92c6f592b0275;
          end

        21:
          begin
            tmp_K = 64'h4a7484aa6ea6e483;
          end

        22:
          begin
            tmp_K = 64'h5cb0a9dcbd41fbd4;
          end

        23:
          begin
            tmp_K = 64'h76f988da831153b5;
          end

        24:
          begin
            tmp_K = 64'h983e5152ee66dfab;
          end
        
        25:
          begin
            tmp_K = 64'ha831c66d2db43210;
          end

        26:
          begin
            tmp_K = 64'hb00327c898fb213f;
          end
        
        27:
          begin
            tmp_K = 64'hbf597fc7beef0ee4;
          end

        28:
          begin
            tmp_K = 64'hc6e00bf33da88fc2;
          end

        29:
          begin
            tmp_K = 64'hd5a79147930aa725;
          end

        30:
          begin
            tmp_K = 64'h06ca6351e003826f;
          end

        31:
          begin
            tmp_K = 64'h142929670a0e6e70;
          end

        32:
          begin
            tmp_K = 64'h27b70a8546d22ffc;
          end

        33:
          begin
            tmp_K = 64'h2e1b21385c26c926;
          end

        34:
          begin
            tmp_K = 64'h4d2c6dfc5ac42aed;
          end

        35:
          begin
            tmp_K = 64'h53380d139d95b3df;
          end

        36:
          begin
            tmp_K = 64'h650a73548baf63de;
          end

        37:
          begin
            tmp_K = 64'h766a0abb3c77b2a8;
          end

        38:
          begin
            tmp_K = 64'h81c2c92e47edaee6;
          end

        39:
          begin
            tmp_K = 64'h92722c851482353b;
          end

        40:
          begin
            tmp_K = 64'ha2bfe8a14cf10364;
          end

        41:
          begin
            tmp_K = 64'ha81a664bbc423001;
          end

        42:
          begin
            tmp_K = 64'hc24b8b70d0f89791;
          end
        
        43:
          begin
            tmp_K = 64'hc76c51a30654be30;
          end
        
        44:
          begin
            tmp_K = 64'hd192e819d6ef5218;
          end

        45:
          begin
            tmp_K = 64'hd69906245565a910;
          end
        
        46:
          begin
            tmp_K = 64'hf40e35855771202a;
          end
        
        47:
          begin
            tmp_K = 64'h106aa07032bbd1b8;
          end
        
        48:
          begin
            tmp_K = 64'h19a4c116b8d2d0c8;
          end
        
        49:
          begin
            tmp_K = 64'h1e376c085141ab53;
          end

        50:
          begin
            tmp_K = 64'h2748774cdf8eeb99;
          end

        51:
          begin
            tmp_K = 64'h34b0bcb5e19b48a8;
          end

        52:
          begin
            tmp_K = 64'h391c0cb3c5c95a63;
          end

        53:
          begin
            tmp_K = 64'h4ed8aa4ae3418acb;
          end

        54:
          begin
            tmp_K = 64'h5b9cca4f7763e373;
          end

        55:
          begin
            tmp_K = 64'h682e6ff3d6b2b8a3;
          end

        56:
          begin
            tmp_K = 64'h748f82ee5defb2fc;
          end
        
        57:
          begin
            tmp_K = 64'h78a5636f43172f60;
          end
        
        58:
          begin
            tmp_K = 64'h84c87814a1f0ab72;
          end
        
        59:
          begin
            tmp_K = 64'h8cc702081a6439ec;
          end

        60:
          begin
            tmp_K = 64'h90befffa23631e28;
          end

        61:
          begin
            tmp_K = 64'ha4506cebde82bde9;
          end

        62:
          begin
            tmp_K = 64'hbef9a3f7b2c67915;
          end

        63:
          begin
            tmp_K = 64'hc67178f2e372532b;
          end

        64:
          begin
            tmp_K = 64'hca273eceea26619c;
          end

        65:
          begin
            tmp_K = 64'hd186b8c721c0c207;
          end

        66:
          begin
            tmp_K = 64'heada7dd6cde0eb1e;
          end

        67:
          begin
            tmp_K = 64'hf57d4f7fee6ed178;
          end

        68:
          begin
            tmp_K = 64'h06f067aa72176fba;
          end

        69:
          begin
            tmp_K = 64'h0a637dc5a2c898a6;
          end

        70:
          begin
            tmp_K = 64'h113f9804bef90dae;
          end

        71:
          begin
            tmp_K = 64'h1b710b35131c471b;
          end

        72:
          begin
            tmp_K = 64'h28db77f523047d84;
          end

        73:
          begin
            tmp_K = 64'h32caab7b40c72493;
          end

        74:
          begin
            tmp_K = 64'h3c9ebe0a15c9bebc;
          end

        75:
          begin
            tmp_K = 64'h431d67c49c100d4c;
          end
        
        76:
          begin
            tmp_K = 64'h4cc5d4becb3e42b6;
          end

        77:
          begin
            tmp_K = 64'h597f299cfc657e2a;
          end

        78:
          begin
            tmp_K = 64'h5fcb6fab3ad6faec;
          end
        
        79:
          begin
            tmp_K = 64'h6c44198c4a475817;
          end

        default:
          begin
            tmp_K = 64'h0000000000000000;
          end
      endcase // case (addr)
    end // block: addr_mux
endmodule // sha512_k_constants

//======================================================================
// sha512_k_constants.v
//======================================================================


//======================================================================
//
// sha512_w_mem_regs.v
// -------------------
// The W memory for the SHA-512 core. This version uses 16
// 32-bit registers as a sliding window to generate the 64 words.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2014 NORDUnet A/S
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// - Redistributions of source code must retain the above copyright notice,
//   this list of conditions and the following disclaimer.
//
// - Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// - Neither the name of the NORDUnet nor the names of its contributors may
//   be used to endorse or promote products derived from this software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module sha512_w_mem(
                    input wire            clk,
                    input wire            reset_n,

                    input wire [1023 : 0] block,

                    input wire            init,
                    input wire            next,
                    output wire [63 : 0]  w
                   );


  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter CTRL_IDLE   = 1'b0;
  parameter CTRL_UPDATE = 1'b1;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [63 : 0] w_mem [0 : 15];
  reg [63 : 0] w_mem00_new;
  reg [63 : 0] w_mem01_new;
  reg [63 : 0] w_mem02_new;
  reg [63 : 0] w_mem03_new;
  reg [63 : 0] w_mem04_new;
  reg [63 : 0] w_mem05_new;
  reg [63 : 0] w_mem06_new;
  reg [63 : 0] w_mem07_new;
  reg [63 : 0] w_mem08_new;
  reg [63 : 0] w_mem09_new;
  reg [63 : 0] w_mem10_new;
  reg [63 : 0] w_mem11_new;
  reg [63 : 0] w_mem12_new;
  reg [63 : 0] w_mem13_new;
  reg [63 : 0] w_mem14_new;
  reg [63 : 0] w_mem15_new;
  reg          w_mem_we;

  reg [6 : 0] w_ctr_reg;
  reg [6 : 0] w_ctr_new;
  reg         w_ctr_we;
  reg         w_ctr_inc;
  reg         w_ctr_rst;

  reg         sha512_w_mem_ctrl_reg;
  reg         sha512_w_mem_ctrl_new;
  reg         sha512_w_mem_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [63 : 0] w_tmp;
  reg [63 : 0] w_new;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign w = w_tmp;


  //----------------------------------------------------------------
  // reg_update
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin : reg_update
      if (!reset_n)
        begin
          w_mem[00]             <= 64'h0000000000000000;
          w_mem[01]             <= 64'h0000000000000000;
          w_mem[02]             <= 64'h0000000000000000;
          w_mem[03]             <= 64'h0000000000000000;
          w_mem[04]             <= 64'h0000000000000000;
          w_mem[05]             <= 64'h0000000000000000;
          w_mem[06]             <= 64'h0000000000000000;
          w_mem[07]             <= 64'h0000000000000000;
          w_mem[08]             <= 64'h0000000000000000;
          w_mem[09]             <= 64'h0000000000000000;
          w_mem[10]             <= 64'h0000000000000000;
          w_mem[11]             <= 64'h0000000000000000;
          w_mem[12]             <= 64'h0000000000000000;
          w_mem[13]             <= 64'h0000000000000000;
          w_mem[14]             <= 64'h0000000000000000;
          w_mem[15]             <= 64'h0000000000000000;
          w_ctr_reg             <= 7'h00;
          sha512_w_mem_ctrl_reg <= CTRL_IDLE;
        end
      else
        begin
          if (w_mem_we)
            begin
              w_mem[00] <= w_mem00_new;
              w_mem[01] <= w_mem01_new;
              w_mem[02] <= w_mem02_new;
              w_mem[03] <= w_mem03_new;
              w_mem[04] <= w_mem04_new;
              w_mem[05] <= w_mem05_new;
              w_mem[06] <= w_mem06_new;
              w_mem[07] <= w_mem07_new;
              w_mem[08] <= w_mem08_new;
              w_mem[09] <= w_mem09_new;
              w_mem[10] <= w_mem10_new;
              w_mem[11] <= w_mem11_new;
              w_mem[12] <= w_mem12_new;
              w_mem[13] <= w_mem13_new;
              w_mem[14] <= w_mem14_new;
              w_mem[15] <= w_mem15_new;
            end

          if (w_ctr_we)
            begin
              w_ctr_reg <= w_ctr_new;
            end

          if (sha512_w_mem_ctrl_we)
            begin
              sha512_w_mem_ctrl_reg <= sha512_w_mem_ctrl_new;
            end
        end
    end // reg_update


  //----------------------------------------------------------------
  // select_w
  //
  // Mux for the external read operation. This is where we exract
  // the W variable.
  //----------------------------------------------------------------
  always @*
    begin : select_w
      if (w_ctr_reg < 16)
        begin
          w_tmp = w_mem[w_ctr_reg[3 : 0]];
        end
      else
        begin
          w_tmp = w_new;
        end
    end // select_w


  //----------------------------------------------------------------
  // w_new_logic
  //
  // Logic that calculates the next value to be inserted into
  // the sliding window of the memory.
  //----------------------------------------------------------------
  always @*
    begin : w_mem_update_logic
      reg [63 : 0] w_0;
      reg [63 : 0] w_1;
      reg [63 : 0] w_9;
      reg [63 : 0] w_14;
      reg [63 : 0] d0;
      reg [63 : 0] d1;

      w_mem00_new = 64'h0000000000000000;
      w_mem01_new = 64'h0000000000000000;
      w_mem02_new = 64'h0000000000000000;
      w_mem03_new = 64'h0000000000000000;
      w_mem04_new = 64'h0000000000000000;
      w_mem05_new = 64'h0000000000000000;
      w_mem06_new = 64'h0000000000000000;
      w_mem07_new = 64'h0000000000000000;
      w_mem08_new = 64'h0000000000000000;
      w_mem09_new = 64'h0000000000000000;
      w_mem10_new = 64'h0000000000000000;
      w_mem11_new = 64'h0000000000000000;
      w_mem12_new = 64'h0000000000000000;
      w_mem13_new = 64'h0000000000000000;
      w_mem14_new = 64'h0000000000000000;
      w_mem15_new = 64'h0000000000000000;
      w_mem_we    = 0;

      w_0  = w_mem[0];
      w_1  = w_mem[1];
      w_9  = w_mem[9];
      w_14 = w_mem[14];

      d0 = {w_1[0],     w_1[63 : 1]} ^ // ROTR1
           {w_1[7 : 0], w_1[63 : 8]} ^ // ROTR8
           {7'b0000000, w_1[63 : 7]};  // SHR7

      d1 = {w_14[18 : 0], w_14[63 : 19]} ^ // ROTR19
           {w_14[60 : 0], w_14[63 : 61]} ^ // ROTR61
           {6'b000000,    w_14[63 : 6]};   // SHR6

      w_new = w_0 + d0 + w_9 + d1;

      if (init)
        begin
          w_mem00_new = block[1023 : 960];
          w_mem01_new = block[959  : 896];
          w_mem02_new = block[895  : 832];
          w_mem03_new = block[831  : 768];
          w_mem04_new = block[767  : 704];
          w_mem05_new = block[703  : 640];
          w_mem06_new = block[639  : 576];
          w_mem07_new = block[575  : 512];
          w_mem08_new = block[511  : 448];
          w_mem09_new = block[447  : 384];
          w_mem10_new = block[383  : 320];
          w_mem11_new = block[319  : 256];
          w_mem12_new = block[255  : 192];
          w_mem13_new = block[191  : 128];
          w_mem14_new = block[127  :  64];
          w_mem15_new = block[63   :   0];
          w_mem_we    = 1;
        end
      else if (w_ctr_reg > 15)
        begin
          w_mem00_new = w_mem[01];
          w_mem01_new = w_mem[02];
          w_mem02_new = w_mem[03];
          w_mem03_new = w_mem[04];
          w_mem04_new = w_mem[05];
          w_mem05_new = w_mem[06];
          w_mem06_new = w_mem[07];
          w_mem07_new = w_mem[08];
          w_mem08_new = w_mem[09];
          w_mem09_new = w_mem[10];
          w_mem10_new = w_mem[11];
          w_mem11_new = w_mem[12];
          w_mem12_new = w_mem[13];
          w_mem13_new = w_mem[14];
          w_mem14_new = w_mem[15];
          w_mem15_new = w_new;
          w_mem_we    = 1;
        end
    end // w_mem_update_logic


  //----------------------------------------------------------------
  // w_ctr
  // W schedule adress counter. Counts from 0x10 to 0x3f and
  // is used to expand the block into words.
  //----------------------------------------------------------------
  always @*
    begin : w_ctr
      w_ctr_new = 0;
      w_ctr_we  = 0;

      if (w_ctr_rst)
        begin
          w_ctr_new = 7'h00;
          w_ctr_we  = 1;
        end

      if (w_ctr_inc)
        begin
          w_ctr_new = w_ctr_reg + 7'h01;
          w_ctr_we  = 1;
        end
    end // w_ctr


  //----------------------------------------------------------------
  // sha512_w_mem_fsm
  // Logic for the w shedule FSM.
  //----------------------------------------------------------------
  always @*
    begin : sha512_w_mem_fsm
      w_ctr_rst = 0;
      w_ctr_inc = 0;

      sha512_w_mem_ctrl_new = CTRL_IDLE;
      sha512_w_mem_ctrl_we  = 0;

      case (sha512_w_mem_ctrl_reg)
        CTRL_IDLE:
          begin
            if (init)
              begin
                w_ctr_rst             = 1;
                sha512_w_mem_ctrl_new = CTRL_UPDATE;
                sha512_w_mem_ctrl_we  = 1;
              end
          end

        CTRL_UPDATE:
          begin
            if (next)
              begin
                w_ctr_inc = 1;
              end

            if (w_ctr_reg == 7'h3f)
              begin
                sha512_w_mem_ctrl_new = CTRL_IDLE;
                sha512_w_mem_ctrl_we  = 1;
              end
          end
      endcase // case (sha512_ctrl_reg)
    end // sha512_ctrl_fsm

endmodule // sha512_w_mem

//======================================================================
// sha512_w_mem.v
//======================================================================
