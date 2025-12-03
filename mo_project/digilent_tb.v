//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04/12/2023 10:18:28 AM
// Design Name: 
// Module Name: digilent_tb
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////
`timescale 1ns / 1ps

module digilent_tb;
    reg user_btnc;
	reg clk100;
	wire  serial_tx;
	reg serial_rx;
	wire user_led0;
	wire user_led1;
	wire user_led2;
	wire user_led3;
	wire user_led4;
	wire user_led5;
	wire user_led6;
	wire user_led7;
	wire user_led8;
	wire user_led9;
	wire user_led10;
	wire user_led11;
	wire user_led12;
	wire user_led13;
	wire user_led14;
	wire user_led15;


    digilent_basys3 UUT (.user_btnc(user_btnc),
     .clk100(clk100), 
     .serial_tx(serial_tx),
     .serial_rx(serial_rx),
     .user_led0(user_led0),
     .user_led1(user_led1),
     .user_led2(user_led2),
     .user_led3(user_led3),
     .user_led4(user_led4),
     .user_led5(user_led5),
     .user_led6(user_led6),
     .user_led7(user_led7),
     .user_led8(user_led8),
     .user_led9(user_led9),
     .user_led10(user_led10),
     .user_led11(user_led11),
     .user_led12(user_led12),
     .user_led13(user_led13),
     .user_led14(user_led14),
     .user_led15(user_led15));
    
    initial // initial block executes only once
        begin
            // values for a and b
            user_btnc = 0;
            serial_rx = 0;
            clk100 = 1'b0;
            forever #3 clk100 = ~clk100;
        end
endmodule
