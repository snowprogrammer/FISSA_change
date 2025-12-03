#############  INIT SIMULATIONS #############
set regs_file /home/zhao/mo_project/total2/total2_wop_1_bitflip_1/faulted_regs.yaml
set state_file /home/zhao/mo_project/total2/total2_wop_1_bitflip_1/results/total2_wop_1.json
set f [open $state_file w]
puts $f "{"
puts $f "\t\"start\": \"[clock format [clock seconds] -format "%Y/%m/%d:%H:%M:%S"]\","
close $f

set f [open $regs_file r]
set reg_file_data [read $f]
close $f

###### INIT VARIABLES ######
### CONTROL ###
set periode 8
set half_periode [expr {$periode / 2}]

set start 10142
set nb_sim 0  ;# Simulation number
set sim_active 1 ;# Active sim Boolean
set cycle_ref 1558 ;# Setting the number of reference cycles for the complete simulation
set cycle_curr 0
set avoid_log_registers_list {}
set log_registers_list {}

### FAULTED REGISTER ###
set threat ""
set width_register 0
set faulted_register ""

### DETECTED ERRORS ###
set value_end_pc 0
set cycle_ill_insn ""

### STATUS END ###
set status_end -1 ;# End of simulation code (0: reference simulation / 1: crash / 2: detect / 3: success / 4: silence)

#############  FIRST SIM #############
###### JUMP TO ATTACK START ######
run "$start ns"

##---------------------
run [expr $periode * $cycle_ref - $now / 1000]  ns

# while {$cycle_curr <= $cycle_ref} {
#     incr cycle_curr
#     run "$periode ns"
#     set value_pc [examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o]
#     set value_insn_pc [examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/instr_rdata_id_o]
#     if {([expr {$value_pc} == {"32'h0000022c"}]) && ([expr {$value_insn_pc} == {"32'hfa010113"}])} {
#         set cycle_ill_insn [expr $now / 1000]
#     }
# }

#############  CHECKING SIM VALUES #############
## CHECK ENDING CYCLE ##
set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;# Vérification du numéro du cycle actuel
set status_end 0
set cycle_curr 0

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[join [lrange $nom_reg_list end-1 end] "/"]\": \"[examine -hex $reg]\","
    }
}


#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 0 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 1 #############
set nb_sim 1
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10142 ns"
run "10142 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10142 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_basesoc_state
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 1 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 2 #############
set nb_sim 2
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10150 ns"
run "10150 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10150 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_basesoc_state
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 2 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 3 #############
set nb_sim 3
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10158 ns"
run "10158 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10158 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_basesoc_state
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 3 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 4 #############
set nb_sim 4
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10166 ns"
run "10166 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10166 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_basesoc_state
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 4 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 5 #############
set nb_sim 5
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10174 ns"
run "10174 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10174 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_basesoc_state
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 5 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 6 #############
set nb_sim 6
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10142 ns"
run "10142 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10142 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_done
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 6 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 7 #############
set nb_sim 7
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10150 ns"
run "10150 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10150 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_done
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 7 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 8 #############
set nb_sim 8
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10158 ns"
run "10158 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10158 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_done
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 8 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 9 #############
set nb_sim 9
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10166 ns"
run "10166 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10166 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_done
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 9 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 10 #############
set nb_sim 10
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10174 ns"
run "10174 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10174 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_done
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 10 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 11 #############
set nb_sim 11
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10142 ns"
run "10142 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10142 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_csr_bankarray_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 11 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 12 #############
set nb_sim 12
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10150 ns"
run "10150 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10150 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_csr_bankarray_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 12 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 13 #############
set nb_sim 13
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10158 ns"
run "10158 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10158 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_csr_bankarray_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 13 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 14 #############
set nb_sim 14
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10166 ns"
run "10166 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10166 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_csr_bankarray_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 14 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 15 #############
set nb_sim 15
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10174 ns"
run "10174 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10174 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_csr_bankarray_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 15 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 16 #############
set nb_sim 16
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10142 ns"
run "10142 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10142 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_grant
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 16 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 17 #############
set nb_sim 17
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10150 ns"
run "10150 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10150 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_grant
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 17 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 18 #############
set nb_sim 18
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10158 ns"
run "10158 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10158 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_grant
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 18 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 19 #############
set nb_sim 19
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10166 ns"
run "10166 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10166 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_grant
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 19 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 20 #############
set nb_sim 20
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10174 ns"
run "10174 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10174 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/builder_grant
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 20 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 21 #############
set nb_sim 21
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10142 ns"
run "10142 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10142 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 0
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 21 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 22 #############
set nb_sim 22
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10150 ns"
run "10150 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10150 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 0
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 22 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 23 #############
set nb_sim 23
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10158 ns"
run "10158 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10158 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 0
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 23 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 24 #############
set nb_sim 24
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10166 ns"
run "10166 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10166 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 0
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 24 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 25 #############
set nb_sim 25
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10174 ns"
run "10174 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10174 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 0
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 25 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 26 #############
set nb_sim 26
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10142 ns"
run "10142 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10142 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 1
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 26 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 27 #############
set nb_sim 27
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10150 ns"
run "10150 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10150 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 1
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 27 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 28 #############
set nb_sim 28
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10158 ns"
run "10158 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10158 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 1
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 28 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 29 #############
set nb_sim 29
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10166 ns"
run "10166 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10166 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 1
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 29 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 30 #############
set nb_sim 30
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10174 ns"
run "10174 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10174 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 1
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 30 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 31 #############
set nb_sim 31
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10142 ns"
run "10142 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10142 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 2
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 31 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 32 #############
set nb_sim 32
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10150 ns"
run "10150 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10150 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 2
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 32 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 33 #############
set nb_sim 33
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10158 ns"
run "10158 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10158 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 2
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 33 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 34 #############
set nb_sim 34
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10166 ns"
run "10166 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10166 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 2
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 34 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 35 #############
set nb_sim 35
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10174 ns"
run "10174 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10174 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 2
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 35 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 36 #############
set nb_sim 36
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10142 ns"
run "10142 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10142 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 3
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 36 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 37 #############
set nb_sim 37
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10150 ns"
run "10150 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10150 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 3
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 37 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 38 #############
set nb_sim 38
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10158 ns"
run "10158 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10158 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 3
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 38 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 39 #############
set nb_sim 39
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10166 ns"
run "10166 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10166 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 3
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 39 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 40 #############
set nb_sim 40
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10174 ns"
run "10174 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10174 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 4
set faulted_register sim:/digilent_tb/UUT/builder_slave_sel_r
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register > 1} {
    set bit_attacked 3
    set bit_flipped $bit_attacked
    set value_curr_reg [examine -bin $faulted_register\[{$bit_attacked}\]]
    set value [lindex [split $value_curr_reg b] 1]
    set bitflip_faulted_register [expr $value^1]
    force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_register'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 40 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 41 #############
set nb_sim 41
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10142 ns"
run "10142 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10142 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_interface0_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 41 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 42 #############
set nb_sim 42
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10150 ns"
run "10150 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10150 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_interface0_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 42 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 43 #############
set nb_sim 43
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10158 ns"
run "10158 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10158 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_interface0_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 43 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 44 #############
set nb_sim 44
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10166 ns"
run "10166 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10166 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_interface0_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 44 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 45 #############
set nb_sim 45
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10174 ns"
run "10174 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10174 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_interface0_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 45 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 46 #############
set nb_sim 46
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10142 ns"
run "10142 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10142 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_interface1_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 46 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 47 #############
set nb_sim 47
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10150 ns"
run "10150 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10150 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_interface1_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 47 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 48 #############
set nb_sim 48
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10158 ns"
run "10158 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10158 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_interface1_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 48 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 49 #############
set nb_sim 49
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10166 ns"
run "10166 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10166 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_interface1_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 49 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 50 #############
set nb_sim 50
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10174 ns"
run "10174 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10174 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_interface1_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 50 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 51 #############
set nb_sim 51
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10142 ns"
run "10142 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10142 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 51 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 52 #############
set nb_sim 52
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10150 ns"
run "10150 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10150 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 52 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 53 #############
set nb_sim 53
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10158 ns"
run "10158 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10158 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 53 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 54 #############
set nb_sim 54
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10166 ns"
run "10166 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10166 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 54 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 55 #############
set nb_sim 55
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "10174 ns"
run "10174 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 10174 - $start] / $periode]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "bitflip"
set width_register 1
set faulted_register sim:/digilent_tb/UUT/main_basesoc_ram_bus_ack
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$width_register == 1} {
    set value_curr_reg [examine -bin $faulted_register]
    set value [lindex [split $value_curr_reg b] 1]
    set bf [expr {$value^1}]
    set bit_flipped 0
    force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
}

###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
run [expr $periode * $cycle_ref - $now / 1000]  ns
while {$sim_active == 1} {
    set value_pc [examine -hex /digilent_tb/UUT/VexRiscv/IBusCachedPlugin_fetchPc_pcReg]
    set g_authenticated [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 10 11]
    set crash_flag [examine -hex /digilent_tb/UUT/VexRiscv/CsrPlugin_exceptionPortCtrl_exceptionContext_code]
    set detect_sw [string range [lindex [lindex  [examine -hex /digilent_tb/UUT/sram] 0] 4] 6 7]
    set detect_hw [examine -hex /digilent_tb/UUT/cm_d]
    set correct [examine -hex /digilent_tb/UUT/cm_c]    
    if {([expr {$crash_flag} != {"4'hx"}]) || ([expr {$now > 15864000} ])} {
        set status_end 1
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_hw} == {"1'h1"}])} {
        set status_end 2
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } elseif {([expr {$detect_sw} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 3
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 4
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }     
    } elseif {([expr {$g_authenticated} == {"01"}])} {
        if {([expr {$correct} == {"1'h1"}])} {
            set status_end 5
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        } else {
            set status_end 6
            set sim_active 0
            set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
        }
    } elseif {([expr {$correct} == {"1'h1"}])} {
        set status_end 7
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    } else {
        set status_end 8
        set sim_active 0
        set check_cycle [expr [expr $now / 1000 - $start] / $periode] ;
    }
}

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"RegFilePlugin_regFile/rf$j\": \"[examine -hex /digilent_tb/UUT/VexRiscv/RegFilePlugin_regFile\[{$j}\]]\","
}

#---- Log Sram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"sram/sr$j\": \"[examine -hex /digilent_tb/UUT/sram\[{$j}\]]\","
}

#---- Log Main_ram ----
for {set j 0} {$j < 2048} {incr j} {
    puts $f "\t\t\"main_ram/mr$j\": \"[examine -hex /digilent_tb/UUT/main_ram\[{$j}\]]\","
}

#---- Log Storage ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage/st$j\": \"[examine -hex /digilent_tb/UUT/storage\[{$j}\]]\","
}

#---- Log Storage1 ----
for {set j 0} {$j < 16} {incr j} {
    puts $f "\t\t\"storage_1/st1$j\": \"[examine -hex /digilent_tb/UUT/storage_1\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"threat\": \"$threat\","
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
    # Faulted register 0
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_register,"
    puts $f "\t\t\"bit_flipped\": $bit_flipped,"
}

 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 55 #############
# Write date of end
set f [open $state_file a]
puts $f "\"end\": \"[clock format [clock seconds] -format "%Y/%m/%d:%H:%M:%S"]\""
puts $f "}"
close $f

# Exit the simulation
exit
#------------------------------------