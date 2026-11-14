# Coverage

Windows 10 22H2 is the oracle. Per-area numbers below are the SUMMARY lines of runs on a Windows 10 guest (build 19045, ntdll 10.0.19041.2788); see [VALIDATION.md](VALIDATION.md). Export counts are a **static source-level inventory** (`tools/coverage.py --preprocess`): they show an export is invoked, not that its assertions are deep.

- Reference: ntdll 10.0.19041.2788, 2,433 exports (2,432 named, one ordinal-only).
- 164 areas (executables), 3718 tests run (administrator), 3718 tests run (standard user).
- 1950 of 2,432 named exports have a static invocation candidate; 482 do not.
- Of the 482 without one: **215 justified** (`tools/uncovered_justified.txt`, with a reason each) and **267 untested** (`tools/uncovered.txt` minus the justified list).
- Nt/Zw pairs share an RVA: behavior is tested through one name and the alias relationship is asserted; `export_surface` checks are existence/alias integrity and are not behavioral coverage.

## Areas on Windows 10 (administrator / standard user)

| Area | Tests adm | Failed adm | Skipped adm | Checks adm pass/fail | Tests std | Failed std | Skipped std | Checks std pass/fail |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| [alpc_attr](tests/alpc_attr/) | 9 | 0 | 0 | 244 / 0 | 9 | 0 | 0 | 244 / 0 |
| [alpc_complist](tests/alpc_complist/) | 3 | 0 | 0 | 118 / 0 | 3 | 0 | 0 | 118 / 0 |
| [alpc_port](tests/alpc_port/) | 9 | 0 | 0 | 286 / 0 | 9 | 0 | 0 | 286 / 0 |
| [core_smoke](tests/core_smoke/) | 3 | 0 | 0 | 4 / 0 | 3 | 0 | 0 | 4 / 0 |
| [crt_algorithms](tests/crt_algorithms/) | 159 | 0 | 0 | 45166 / 0 | 159 | 0 | 0 | 45166 / 0 |
| [crt_strings](tests/crt_strings/) | 181 | 0 | 0 | 743 / 0 | 181 | 0 | 0 | 743 / 0 |
| [etw_wnf_sqm_dbg_a_dbg](tests/etw_wnf_sqm_dbg_a_dbg/) | 10 | 0 | 0 | 104 / 0 | 10 | 0 | 0 | 104 / 0 |
| [etw_wnf_sqm_dbg_a_etw](tests/etw_wnf_sqm_dbg_a_etw/) | 21 | 0 | 0 | 241 / 0 | 21 | 0 | 0 | 241 / 0 |
| [etw_wnf_sqm_dbg_b_etw](tests/etw_wnf_sqm_dbg_b_etw/) | 13 | 0 | 0 | 121 / 0 | 13 | 0 | 0 | 121 / 0 |
| [etw_wnf_sqm_dbg_b_sqm](tests/etw_wnf_sqm_dbg_b_sqm/) | 6 | 0 | 0 | 173 / 0 | 6 | 0 | 0 | 173 / 0 |
| [etw_wnf_sqm_dbg_b_tracedb](tests/etw_wnf_sqm_dbg_b_tracedb/) | 9 | 0 | 0 | 310 / 0 | 9 | 0 | 0 | 310 / 0 |
| [export_surface](tests/export_surface/) | 5 | 0 | 0 | 9753 / 0 | 5 | 0 | 0 | 9753 / 0 |
| [harness_checks](tests/harness_checks/) | 11 | 0 | 1 | 39 / 0 | 11 | 0 | 1 | 37 / 0 |
| [ldr_dllpath](tests/ldr_dllpath/) | 9 | 0 | 0 | 43 / 0 | 9 | 0 | 0 | 43 / 0 |
| [ldr_image](tests/ldr_image/) | 78 | 0 | 0 | 283 / 0 | 78 | 0 | 0 | 283 / 0 |
| [ldr_imagefile](tests/ldr_imagefile/) | 10 | 0 | 0 | 179 / 0 | 10 | 0 | 1 | 165 / 0 |
| [ldr_modules](tests/ldr_modules/) | 15 | 0 | 0 | 152 / 0 | 15 | 0 | 0 | 152 / 0 |
| [ldr_resource](tests/ldr_resource/) | 14 | 0 | 0 | 392 / 0 | 14 | 0 | 0 | 392 / 0 |
| [nt_cancel_io](tests/nt_cancel_io/) | 16 | 0 | 0 | 113 / 0 | 16 | 0 | 0 | 113 / 0 |
| [nt_create_open_a_io](tests/nt_create_open_a_io/) | 8 | 0 | 0 | 60 / 0 | 8 | 0 | 0 | 60 / 0 |
| [nt_create_open_a_ktm](tests/nt_create_open_a_ktm/) | 12 | 0 | 0 | 88 / 0 | 12 | 0 | 0 | 88 / 0 |
| [nt_create_open_a_objects](tests/nt_create_open_a_objects/) | 21 | 0 | 0 | 196 / 0 | 21 | 0 | 0 | 196 / 0 |
| [nt_create_open_a_priv](tests/nt_create_open_a_priv/) | 13 | 0 | 0 | 80 / 0 | 13 | 0 | 1 | 77 / 0 |
| [nt_create_open_a_proc](tests/nt_create_open_a_proc/) | 15 | 0 | 0 | 101 / 0 | 15 | 0 | 0 | 101 / 0 |
| [nt_create_open_b_file](tests/nt_create_open_b_file/) | 5 | 0 | 0 | 111 / 0 | 5 | 0 | 0 | 111 / 0 |
| [nt_create_open_b_key](tests/nt_create_open_b_key/) | 6 | 0 | 0 | 96 / 0 | 6 | 0 | 0 | 96 / 0 |
| [nt_create_open_b_misc](tests/nt_create_open_b_misc/) | 8 | 0 | 0 | 91 / 0 | 8 | 0 | 0 | 91 / 0 |
| [nt_create_open_b_obj](tests/nt_create_open_b_obj/) | 8 | 0 | 0 | 136 / 0 | 8 | 0 | 0 | 136 / 0 |
| [nt_create_open_b_proc](tests/nt_create_open_b_proc/) | 8 | 0 | 0 | 134 / 0 | 8 | 0 | 0 | 134 / 0 |
| [nt_create_open_b_sync](tests/nt_create_open_b_sync/) | 8 | 0 | 0 | 159 / 0 | 8 | 0 | 0 | 159 / 0 |
| [nt_create_open_b_tm](tests/nt_create_open_b_tm/) | 3 | 0 | 0 | 57 / 0 | 3 | 0 | 0 | 57 / 0 |
| [nt_create_open_b_userproc](tests/nt_create_open_b_userproc/) | 2 | 0 | 0 | 25 / 0 | 2 | 0 | 0 | 25 / 0 |
| [nt_file](tests/nt_file/) | 161 | 0 | 0 | 1137 / 0 | 161 | 0 | 0 | 1137 / 0 |
| [nt_other_1_a_atom](tests/nt_other_1_a_atom/) | 7 | 0 | 0 | 55 / 0 | 7 | 0 | 0 | 55 / 0 |
| [nt_other_1_a_ctx](tests/nt_other_1_a_ctx/) | 5 | 0 | 0 | 19 / 0 | 5 | 0 | 0 | 19 / 0 |
| [nt_other_1_a_file](tests/nt_other_1_a_file/) | 9 | 0 | 0 | 136 / 0 | 9 | 0 | 0 | 136 / 0 |
| [nt_other_1_a_kobj](tests/nt_other_1_a_kobj/) | 10 | 0 | 0 | 101 / 0 | 10 | 0 | 0 | 101 / 0 |
| [nt_other_1_a_misc](tests/nt_other_1_a_misc/) | 15 | 0 | 0 | 175 / 0 | 15 | 0 | 0 | 175 / 0 |
| [nt_other_1_a_security](tests/nt_other_1_a_security/) | 10 | 0 | 0 | 176 / 0 | 10 | 0 | 0 | 176 / 0 |
| [nt_other_1_a_system](tests/nt_other_1_a_system/) | 8 | 0 | 0 | 65 / 0 | 8 | 0 | 0 | 63 / 0 |
| [nt_other_1_b_io](tests/nt_other_1_b_io/) | 10 | 0 | 0 | 142 / 0 | 10 | 0 | 0 | 142 / 0 |
| [nt_other_1_b_mem](tests/nt_other_1_b_mem/) | 7 | 0 | 0 | 81 / 0 | 7 | 0 | 0 | 81 / 0 |
| [nt_other_1_b_misc](tests/nt_other_1_b_misc/) | 10 | 0 | 0 | 76 / 0 | 10 | 0 | 0 | 76 / 0 |
| [nt_other_1_b_sys](tests/nt_other_1_b_sys/) | 13 | 0 | 0 | 196 / 0 | 13 | 0 | 0 | 196 / 0 |
| [nt_other_2_a_access](tests/nt_other_2_a_access/) | 3 | 0 | 0 | 78 / 0 | 3 | 0 | 0 | 78 / 0 |
| [nt_other_2_a_exec](tests/nt_other_2_a_exec/) | 20 | 0 | 0 | 237 / 0 | 20 | 0 | 0 | 237 / 0 |
| [nt_other_2_a_hive](tests/nt_other_2_a_hive/) | 5 | 0 | 0 | 91 / 0 | 5 | 0 | 3 | 29 / 0 |
| [nt_other_2_a_ktm](tests/nt_other_2_a_ktm/) | 7 | 0 | 0 | 44 / 0 | 7 | 0 | 1 | 42 / 0 |
| [nt_other_2_a_lpc](tests/nt_other_2_a_lpc/) | 3 | 0 | 0 | 58 / 0 | 3 | 0 | 0 | 58 / 0 |
| [nt_other_2_a_misc](tests/nt_other_2_a_misc/) | 5 | 0 | 0 | 55 / 0 | 5 | 0 | 0 | 55 / 0 |
| [nt_other_2_b_io](tests/nt_other_2_b_io/) | 22 | 0 | 1 | 245 / 0 | 22 | 0 | 1 | 245 / 0 |
| [nt_other_2_b_obj](tests/nt_other_2_b_obj/) | 16 | 0 | 0 | 168 / 0 | 16 | 0 | 0 | 168 / 0 |
| [nt_other_2_b_token](tests/nt_other_2_b_token/) | 8 | 0 | 0 | 126 / 0 | 8 | 0 | 0 | 107 / 0 |
| [nt_other_3_a_file](tests/nt_other_3_a_file/) | 24 | 0 | 0 | 179 / 0 | 24 | 0 | 0 | 179 / 0 |
| [nt_other_3_a_key](tests/nt_other_3_a_key/) | 11 | 0 | 0 | 59 / 0 | 11 | 0 | 0 | 59 / 0 |
| [nt_other_3_a_mem](tests/nt_other_3_a_mem/) | 25 | 0 | 0 | 178 / 0 | 25 | 0 | 0 | 178 / 0 |
| [nt_other_3_a_proc](tests/nt_other_3_a_proc/) | 25 | 0 | 0 | 350 / 0 | 25 | 0 | 0 | 239 / 0 |
| [nt_other_3_b_ktm](tests/nt_other_3_b_ktm/) | 3 | 0 | 0 | 65 / 0 | 3 | 0 | 0 | 65 / 0 |
| [nt_other_3_b_misc](tests/nt_other_3_b_misc/) | 14 | 0 | 0 | 70 / 0 | 14 | 0 | 2 | 69 / 0 |
| [nt_other_3_b_port](tests/nt_other_3_b_port/) | 4 | 0 | 0 | 94 / 0 | 4 | 0 | 0 | 94 / 0 |
| [nt_other_3_b_proc](tests/nt_other_3_b_proc/) | 18 | 0 | 0 | 242 / 0 | 18 | 0 | 0 | 242 / 0 |
| [nt_other_3_b_reg](tests/nt_other_3_b_reg/) | 7 | 0 | 0 | 87 / 0 | 7 | 0 | 4 | 49 / 0 |
| [nt_other_3_b_sync](tests/nt_other_3_b_sync/) | 16 | 0 | 0 | 166 / 0 | 16 | 0 | 0 | 166 / 0 |
| [nt_process](tests/nt_process/) | 62 | 0 | 0 | 420 / 0 | 62 | 0 | 0 | 420 / 0 |
| [nt_query_info_a_file](tests/nt_query_info_a_file/) | 8 | 0 | 0 | 136 / 0 | 8 | 0 | 0 | 136 / 0 |
| [nt_query_info_a_misc](tests/nt_query_info_a_misc/) | 9 | 0 | 0 | 130 / 0 | 9 | 0 | 0 | 128 / 0 |
| [nt_query_info_a_obj](tests/nt_query_info_a_obj/) | 9 | 0 | 1 | 186 / 0 | 9 | 0 | 1 | 186 / 0 |
| [nt_query_info_a_sys](tests/nt_query_info_a_sys/) | 13 | 0 | 0 | 103 / 0 | 13 | 0 | 1 | 98 / 0 |
| [nt_query_info_b_file](tests/nt_query_info_b_file/) | 10 | 0 | 0 | 261 / 0 | 10 | 0 | 0 | 256 / 0 |
| [nt_query_info_b_key](tests/nt_query_info_b_key/) | 7 | 0 | 0 | 176 / 0 | 7 | 0 | 1 | 165 / 0 |
| [nt_query_info_b_ktm](tests/nt_query_info_b_ktm/) | 5 | 0 | 1 | 54 / 0 | 5 | 0 | 1 | 54 / 0 |
| [nt_query_info_b_misc](tests/nt_query_info_b_misc/) | 13 | 0 | 0 | 110 / 0 | 13 | 0 | 2 | 107 / 0 |
| [nt_query_info_b_object](tests/nt_query_info_b_object/) | 12 | 0 | 0 | 269 / 0 | 12 | 0 | 0 | 269 / 0 |
| [nt_query_info_b_proc](tests/nt_query_info_b_proc/) | 12 | 0 | 0 | 329 / 0 | 12 | 0 | 0 | 329 / 0 |
| [nt_registry](tests/nt_registry/) | 74 | 0 | 0 | 710 / 0 | 74 | 0 | 0 | 710 / 0 |
| [nt_set_info_a_file](tests/nt_set_info_a_file/) | 5 | 0 | 0 | 45 / 0 | 5 | 0 | 0 | 45 / 0 |
| [nt_set_info_a_ktm](tests/nt_set_info_a_ktm/) | 3 | 0 | 0 | 29 / 0 | 3 | 0 | 0 | 29 / 0 |
| [nt_set_info_a_object](tests/nt_set_info_a_object/) | 9 | 0 | 0 | 90 / 0 | 9 | 0 | 0 | 90 / 0 |
| [nt_set_info_a_process](tests/nt_set_info_a_process/) | 9 | 0 | 0 | 78 / 0 | 9 | 0 | 0 | 78 / 0 |
| [nt_set_info_a_sync](tests/nt_set_info_a_sync/) | 10 | 0 | 0 | 69 / 0 | 10 | 0 | 0 | 69 / 0 |
| [nt_set_info_a_system](tests/nt_set_info_a_system/) | 12 | 0 | 2 | 54 / 0 | 12 | 0 | 1 | 55 / 0 |
| [nt_set_info_a_thread](tests/nt_set_info_a_thread/) | 14 | 0 | 0 | 90 / 0 | 14 | 0 | 0 | 90 / 0 |
| [nt_set_info_a_token](tests/nt_set_info_a_token/) | 10 | 0 | 0 | 73 / 0 | 10 | 0 | 0 | 73 / 0 |
| [nt_set_info_b_file](tests/nt_set_info_b_file/) | 10 | 0 | 0 | 132 / 0 | 10 | 0 | 0 | 132 / 0 |
| [nt_set_info_b_ktm](tests/nt_set_info_b_ktm/) | 3 | 0 | 0 | 80 / 0 | 3 | 0 | 0 | 80 / 0 |
| [nt_set_info_b_obj](tests/nt_set_info_b_obj/) | 13 | 0 | 0 | 263 / 0 | 13 | 0 | 0 | 263 / 0 |
| [nt_set_info_b_sync](tests/nt_set_info_b_sync/) | 14 | 0 | 0 | 148 / 0 | 14 | 0 | 0 | 148 / 0 |
| [nt_set_info_b_sys](tests/nt_set_info_b_sys/) | 13 | 0 | 0 | 75 / 0 | 13 | 0 | 0 | 73 / 0 |
| [nt_sync](tests/nt_sync/) | 120 | 0 | 0 | 917 / 0 | 120 | 0 | 0 | 917 / 0 |
| [nt_thread](tests/nt_thread/) | 35 | 0 | 0 | 198 / 0 | 35 | 0 | 1 | 194 / 0 |
| [nt_token](tests/nt_token/) | 55 | 0 | 0 | 845 / 0 | 55 | 0 | 0 | 837 / 0 |
| [nt_vm](tests/nt_vm/) | 74 | 0 | 0 | 712 / 0 | 74 | 0 | 0 | 712 / 0 |
| [pss_csr_misc_csr](tests/pss_csr_misc_csr/) | 8 | 0 | 0 | 85 / 0 | 8 | 0 | 0 | 85 / 0 |
| [pss_csr_misc_pss](tests/pss_csr_misc_pss/) | 7 | 0 | 0 | 135 / 0 | 7 | 0 | 0 | 135 / 0 |
| [pss_csr_misc_worklist](tests/pss_csr_misc_worklist/) | 3 | 0 | 0 | 66 / 0 | 3 | 0 | 0 | 66 / 0 |
| [pss_csr_misc_wow64](tests/pss_csr_misc_wow64/) | 9 | 0 | 0 | 186 / 0 | 9 | 0 | 0 | 186 / 0 |
| [rtl_bitmap](tests/rtl_bitmap/) | 48 | 0 | 0 | 3272 / 0 | 48 | 0 | 0 | 3272 / 0 |
| [rtl_compression](tests/rtl_compression/) | 60 | 0 | 0 | 1240 / 0 | 60 | 0 | 0 | 1240 / 0 |
| [rtl_context](tests/rtl_context/) | 43 | 0 | 0 | 287 / 0 | 43 | 0 | 0 | 287 / 0 |
| [rtl_conversion](tests/rtl_conversion/) | 90 | 0 | 0 | 1495 / 0 | 90 | 0 | 0 | 1495 / 0 |
| [rtl_create_add_delete_a_acl](tests/rtl_create_add_delete_a_acl/) | 21 | 0 | 0 | 445 / 0 | 21 | 0 | 0 | 445 / 0 |
| [rtl_create_add_delete_a_misc](tests/rtl_create_add_delete_a_misc/) | 23 | 0 | 0 | 365 / 0 | 23 | 0 | 0 | 365 / 0 |
| [rtl_create_add_delete_a_proc](tests/rtl_create_add_delete_a_proc/) | 5 | 0 | 0 | 47 / 0 | 5 | 0 | 0 | 47 / 0 |
| [rtl_create_add_delete_a_sync](tests/rtl_create_add_delete_a_sync/) | 17 | 0 | 0 | 173 / 0 | 17 | 0 | 0 | 173 / 0 |
| [rtl_create_add_delete_b_ds](tests/rtl_create_add_delete_b_ds/) | 10 | 0 | 0 | 279 / 0 | 10 | 0 | 0 | 279 / 0 |
| [rtl_create_add_delete_b_misc](tests/rtl_create_add_delete_b_misc/) | 17 | 0 | 0 | 178 / 0 | 17 | 0 | 1 | 173 / 0 |
| [rtl_create_add_delete_b_sync](tests/rtl_create_add_delete_b_sync/) | 21 | 0 | 0 | 195 / 0 | 21 | 0 | 0 | 195 / 0 |
| [rtl_environment](tests/rtl_environment/) | 46 | 0 | 0 | 718 / 0 | 46 | 0 | 0 | 718 / 0 |
| [rtl_get_appc](tests/rtl_get_appc/) | 7 | 0 | 0 | 69 / 0 | 7 | 0 | 0 | 69 / 0 |
| [rtl_get_lang](tests/rtl_get_lang/) | 7 | 0 | 0 | 167 / 0 | 7 | 0 | 0 | 167 / 0 |
| [rtl_get_path](tests/rtl_get_path/) | 8 | 0 | 0 | 139 / 0 | 8 | 0 | 0 | 139 / 0 |
| [rtl_get_sysinfo](tests/rtl_get_sysinfo/) | 18 | 0 | 0 | 136 / 0 | 18 | 0 | 0 | 136 / 0 |
| [rtl_get_thread](tests/rtl_get_thread/) | 17 | 0 | 0 | 157 / 0 | 17 | 0 | 0 | 157 / 0 |
| [rtl_hash](tests/rtl_hash/) | 70 | 0 | 0 | 7416 / 0 | 70 | 0 | 0 | 7416 / 0 |
| [rtl_heap](tests/rtl_heap/) | 64 | 0 | 0 | 626 / 0 | 64 | 0 | 0 | 626 / 0 |
| [rtl_memory](tests/rtl_memory/) | 62 | 0 | 0 | 4361 / 0 | 62 | 0 | 0 | 4361 / 0 |
| [rtl_net_ip_str_a_obj](tests/rtl_net_ip_str_a_obj/) | 14 | 0 | 0 | 214 / 0 | 14 | 0 | 0 | 214 / 0 |
| [rtl_net_ip_str_a_path](tests/rtl_net_ip_str_a_path/) | 9 | 0 | 0 | 88 / 0 | 9 | 0 | 0 | 88 / 0 |
| [rtl_net_ip_str_a_str](tests/rtl_net_ip_str_a_str/) | 21 | 0 | 0 | 229 / 0 | 21 | 0 | 0 | 229 / 0 |
| [rtl_net_ip_str_b_ip](tests/rtl_net_ip_str_b_ip/) | 9 | 0 | 0 | 475 / 0 | 9 | 0 | 0 | 475 / 0 |
| [rtl_net_ip_str_b_misc](tests/rtl_net_ip_str_b_misc/) | 29 | 0 | 0 | 1058 / 0 | 29 | 0 | 0 | 1058 / 0 |
| [rtl_net_ip_str_b_str](tests/rtl_net_ip_str_b_str/) | 12 | 0 | 0 | 131 / 0 | 12 | 0 | 0 | 131 / 0 |
| [rtl_netaddr](tests/rtl_netaddr/) | 20 | 0 | 0 | 611 / 0 | 20 | 0 | 0 | 611 / 0 |
| [rtl_numeric](tests/rtl_numeric/) | 82 | 0 | 0 | 551 / 0 | 82 | 0 | 0 | 551 / 0 |
| [rtl_path](tests/rtl_path/) | 68 | 0 | 0 | 215 / 0 | 68 | 0 | 0 | 215 / 0 |
| [rtl_path_ext](tests/rtl_path_ext/) | 37 | 0 | 0 | 176 / 0 | 37 | 0 | 0 | 176 / 0 |
| [rtl_query_set_a_data](tests/rtl_query_set_a_data/) | 17 | 0 | 0 | 395 / 0 | 17 | 0 | 0 | 395 / 0 |
| [rtl_query_set_a_misc](tests/rtl_query_set_a_misc/) | 13 | 0 | 0 | 102 / 0 | 13 | 0 | 0 | 102 / 0 |
| [rtl_query_set_a_sys](tests/rtl_query_set_a_sys/) | 16 | 0 | 0 | 157 / 0 | 16 | 0 | 0 | 157 / 0 |
| [rtl_query_set_b_async](tests/rtl_query_set_b_async/) | 5 | 0 | 0 | 101 / 0 | 5 | 0 | 0 | 101 / 0 |
| [rtl_query_set_b_bits_sd](tests/rtl_query_set_b_bits_sd/) | 10 | 0 | 0 | 111 / 0 | 10 | 0 | 0 | 111 / 0 |
| [rtl_query_set_b_env](tests/rtl_query_set_b_env/) | 7 | 0 | 0 | 122 / 0 | 7 | 0 | 0 | 122 / 0 |
| [rtl_query_set_b_misc](tests/rtl_query_set_b_misc/) | 16 | 0 | 0 | 111 / 0 | 16 | 0 | 0 | 112 / 0 |
| [rtl_rest_crt_other_1_a_data](tests/rtl_rest_crt_other_1_a_data/) | 14 | 0 | 0 | 376 / 0 | 14 | 0 | 0 | 376 / 0 |
| [rtl_rest_crt_other_1_a_misc](tests/rtl_rest_crt_other_1_a_misc/) | 18 | 0 | 0 | 334 / 0 | 18 | 0 | 0 | 334 / 0 |
| [rtl_rest_crt_other_1_a_proc](tests/rtl_rest_crt_other_1_a_proc/) | 10 | 0 | 0 | 130 / 0 | 10 | 0 | 0 | 130 / 0 |
| [rtl_rest_crt_other_1_b_ds](tests/rtl_rest_crt_other_1_b_ds/) | 19 | 0 | 0 | 1294 / 0 | 19 | 0 | 0 | 1294 / 0 |
| [rtl_rest_crt_other_1_b_str](tests/rtl_rest_crt_other_1_b_str/) | 17 | 0 | 0 | 451 / 0 | 17 | 0 | 0 | 451 / 0 |
| [rtl_rest_crt_other_1_b_sys](tests/rtl_rest_crt_other_1_b_sys/) | 18 | 0 | 0 | 233 / 0 | 18 | 0 | 0 | 233 / 0 |
| [rtl_rest_crt_other_2_a_exec](tests/rtl_rest_crt_other_2_a_exec/) | 12 | 0 | 0 | 150 / 0 | 12 | 0 | 0 | 150 / 0 |
| [rtl_rest_crt_other_2_a_sec](tests/rtl_rest_crt_other_2_a_sec/) | 12 | 0 | 0 | 230 / 0 | 12 | 0 | 0 | 230 / 0 |
| [rtl_rest_crt_other_2_a_str](tests/rtl_rest_crt_other_2_a_str/) | 8 | 0 | 0 | 198 / 0 | 8 | 0 | 0 | 198 / 0 |
| [rtl_rest_crt_other_2_a_struct](tests/rtl_rest_crt_other_2_a_struct/) | 13 | 0 | 0 | 1017 / 0 | 13 | 0 | 0 | 1017 / 0 |
| [rtl_rest_crt_other_2_b_misc](tests/rtl_rest_crt_other_2_b_misc/) | 24 | 0 | 0 | 778 / 0 | 24 | 0 | 0 | 778 / 0 |
| [rtl_rest_crt_other_2_b_reg](tests/rtl_rest_crt_other_2_b_reg/) | 12 | 0 | 0 | 126 / 0 | 12 | 0 | 0 | 126 / 0 |
| [rtl_rest_crt_other_3_a_crt](tests/rtl_rest_crt_other_3_a_crt/) | 24 | 0 | 0 | 1134 / 0 | 24 | 0 | 0 | 1134 / 0 |
| [rtl_rest_crt_other_3_a_rtl](tests/rtl_rest_crt_other_3_a_rtl/) | 10 | 0 | 0 | 446 / 0 | 10 | 0 | 0 | 446 / 0 |
| [rtl_rest_crt_other_3_b_conv](tests/rtl_rest_crt_other_3_b_conv/) | 8 | 0 | 0 | 199 / 0 | 8 | 0 | 0 | 199 / 0 |
| [rtl_rest_crt_other_3_b_fmt](tests/rtl_rest_crt_other_3_b_fmt/) | 11 | 0 | 0 | 230 / 0 | 11 | 0 | 0 | 230 / 0 |
| [rtl_rest_crt_other_3_b_math](tests/rtl_rest_crt_other_3_b_math/) | 6 | 0 | 0 | 2714 / 0 | 6 | 0 | 0 | 2714 / 0 |
| [rtl_rest_crt_other_3_b_str](tests/rtl_rest_crt_other_3_b_str/) | 9 | 0 | 0 | 347 / 0 | 9 | 0 | 0 | 347 / 0 |
| [rtl_security](tests/rtl_security/) | 93 | 0 | 0 | 585 / 0 | 93 | 0 | 0 | 585 / 0 |
| [rtl_slist](tests/rtl_slist/) | 11 | 0 | 0 | 85 / 0 | 11 | 0 | 0 | 85 / 0 |
| [rtl_status](tests/rtl_status/) | 55 | 0 | 0 | 409 / 0 | 55 | 0 | 0 | 409 / 0 |
| [rtl_strings](tests/rtl_strings/) | 65 | 0 | 0 | 993 / 0 | 65 | 0 | 0 | 993 / 0 |
| [rtl_strings_ext](tests/rtl_strings_ext/) | 35 | 0 | 0 | 267 / 0 | 35 | 0 | 0 | 267 / 0 |
| [rtl_sync](tests/rtl_sync/) | 81 | 0 | 0 | 332 / 0 | 81 | 0 | 0 | 332 / 0 |
| [rtl_tables](tests/rtl_tables/) | 73 | 0 | 0 | 3927 / 0 | 73 | 0 | 0 | 3927 / 0 |
| [rtl_threadpool](tests/rtl_threadpool/) | 28 | 0 | 0 | 28 / 0 | 28 | 0 | 0 | 28 / 0 |
| [rtl_time](tests/rtl_time/) | 93 | 0 | 0 | 432 / 0 | 93 | 0 | 0 | 432 / 0 |
| [tp_iocp](tests/tp_iocp/) | 7 | 0 | 0 | 171 / 0 | 7 | 0 | 0 | 171 / 0 |
| [tp_pool_cfg](tests/tp_pool_cfg/) | 12 | 0 | 0 | 105 / 0 | 12 | 0 | 0 | 105 / 0 |
| [tp_pool_io](tests/tp_pool_io/) | 7 | 0 | 0 | 105 / 0 | 7 | 0 | 0 | 104 / 0 |
| [tp_wfactory](tests/tp_wfactory/) | 5 | 0 | 0 | 130 / 0 | 5 | 0 | 0 | 130 / 0 |

| Total | 3718 | 0 | 6 | 116571 / 0 | 3718 | 0 | 23 | 116273 / 0 |

Most areas have `tests/<area>/EVIDENCE.md`: where each expected value came from (documentation, decompilation of the 22H2 binary, or observed Windows 10 behavior), skips and why.

## Justified without a behavioral test

These exports are deliberately not exercised (no service connection, unsafe even in a disposable VM, or not meaningfully callable). Reasons are in `tools/uncovered_justified.txt`; this is a separate category from untested.

215 exports: `EtwDeliverDataBlock`, `EtwRegisterSecurityProvider`, `EtwSendNotification`, `EvtIntReportAuthzEventAndSourceAsync`, `EvtIntReportEventAndSourceAsync`, `ExpInterlockedPopEntrySListEnd`, `ExpInterlockedPopEntrySListFault`, `ExpInterlockedPopEntrySListResume`, `KiRaiseUserExceptionDispatcher`, `KiUserApcDispatcher`, `KiUserCallbackDispatcher`, `KiUserExceptionDispatcher`, `LdrAppxHandleIntegrityFailure`, `LdrCallEnclave`, `LdrCreateEnclave`, `LdrDeleteEnclave`, `LdrFastFailInLoaderCallout`, `LdrInitShimEngineDynamic`, `LdrInitializeEnclave`, `LdrInitializeThunk`, `LdrLoadEnclaveModule`, `LdrProcessInitializationComplete`, `LdrSetAppCompatDllRedirectionCallback`, `LdrSetDllManifestProber`, `LdrShutdownProcess`, `LdrShutdownThread`, `LdrStandardizeSystemPath`, `NtCallEnclave`, `NtDirectGraphicsCall`, `NtDisableLastKnownGood`, `NtEnableLastKnownGood`, `NtFlushInstallUILanguage`, `NtFreezeRegistry`, `NtFreezeTransactions`, `NtGetCompleteWnfStateSubscription`, `NtInitializeEnclave`, `NtInitializeNlsFiles`, `NtInitializeRegistry`, `NtInitiatePowerAction`, `NtLoadEnclaveData`, `NtManageHotPatch`, `NtManagePartition`, `NtMapCMFModule`, `NtModifyBootEntry`, `NtModifyDriverEntry`, `NtNotifyChangeSession`, `NtPssCaptureVaSpaceBulk`, `NtRaiseHardError`, `NtReadRequestData`, `NtSetSystemPowerState`, `NtShutdownSystem`, `RtlAllocateWnfSerializationGroup`, `RtlApplicationVerifierStop`, `RtlAssert`, `RtlCallEnclaveReturn`, `RtlCleanUpTEBLangLists`, `RtlCompleteProcessCloning`, `RtlConnectToSm`, `RtlConvertToAutoInheritSecurityObject`, `RtlCopyExtendedContext`, `RtlCreateSystemVolumeInformationFolder`, `RtlCreateTagHeap`, `RtlDetectHeapLeaks`, `RtlDosApplyFileIsolationRedirection_Ustr`, `RtlDumpResource`, `RtlEnclaveCallDispatch`, `RtlEnclaveCallDispatchReturn`, `RtlFinalReleaseOutOfProcessMemoryStream`, `RtlFindActivationContextSectionGuid`, `RtlFindActivationContextSectionString`, `RtlFreeNonVolatileToken`, `RtlFreeUserFiberShadowStack`, `RtlHeapTrkInitialize`, `RtlInitCodePageTable`, `RtlInitNlsTables`, `RtlInitializeAtomPackage`, `RtlInitializeNtUserPfn`, `RtlLogStackBackTrace`, `RtlNotifyFeatureUsage`, `RtlPrepareForProcessCloning`, `RtlProcessFlsData`, `RtlProtectHeap`, `RtlPublishWnfStateData`, `RtlRaiseCustomSystemEventTrigger`, `RtlRaiseExceptionForReturnAddressHijack`, `RtlReadThreadProfilingData`, `RtlRegisterThreadWithCsrss`, `RtlRemoteCall`, `RtlReportException`, `RtlReportExceptionEx`, `RtlReportSilentProcessExit`, `RtlReportSqmEscalation`, `RtlResetNtUserPfn`, `RtlResetRtlTranslations`, `RtlRestoreBootStatusDefaults`, `RtlRestoreSystemBootStatusDefaults`, `RtlSendMsgToSm`, `RtlSetImageMitigationPolicy`, `RtlSetPortableOperatingSystem`, `RtlSetProcessDebugInformation`, `RtlSetSystemBootStatus`, `RtlSetUnhandledExceptionFilter`, `RtlSubscribeForFeatureUsageNotification`, `RtlSubscribeWnfStateChangeNotification`, `RtlTestAndPublishWnfStateData`, `RtlUmsThreadYield`, `RtlUnhandledExceptionFilter`, `RtlUnhandledExceptionFilter2`, `RtlUnsubscribeFromFeatureUsageNotifications`, `RtlUnsubscribeWnfNotificationWaitForCompletion`, `RtlUnsubscribeWnfNotificationWithCompletionCallback`, `RtlUnsubscribeWnfStateChangeNotification`, `RtlUnwind`, `RtlUpdateClonedCriticalSection`, `RtlUpdateClonedSRWLock`, `RtlUserFiberStart`, `RtlUserThreadStart`, `RtlWaitForWnfMetaNotification`, `RtlWerpReportException`, `RtlWow64GetCurrentCpuArea`, `RtlWow64LogMessageInEventLogger`, `RtlWriteNonVolatileMemory`, `RtlZombifyActivationContext`, `RtlpCleanupRegistryKeys`, `RtlpConvertAbsoluteToRelativeSecurityAttribute`, `RtlpConvertRelativeToAbsoluteSecurityAttribute`, `RtlpCreateProcessRegistryInfo`, `RtlpExecuteUmsThread`, `RtlpFreezeTimeBias`, `RtlpGetLCIDFromLangInfoNode`, `RtlpGetNameFromLangInfoNode`, `RtlpGetUserOrMachineUILanguage4NLS`, `RtlpInitializeLangRegistryInfo`, `RtlpIsQualifiedLanguage`, `RtlpLoadMachineUIByPolicy`, `RtlpLoadUserUIByPolicy`, `RtlpMergeSecurityAttributeInformation`, `RtlpMuiFreeLangRegistryInfo`, `RtlpMuiRegCreateRegistryInfo`, `RtlpMuiRegFreeRegistryInfo`, `RtlpMuiRegLoadRegistryInfo`, `RtlpNotOwnerCriticalSection`, `RtlpQueryDefaultUILanguage`, `RtlpQueryProcessDebugInformationFromWow64`, `RtlpQueryProcessDebugInformationRemote`, `RtlpSetPreferredUILanguages`, `RtlpSetUserPreferredUILanguages`, `RtlpUmsExecuteYieldThreadEnd`, `RtlpUmsThreadYield`, `RtlpVerifyAndCommitUILanguageSettings`, `SbExecuteProcedure`, `SbSelectProcedure`, `ShipAssertMsgA`, `ShipAssertMsgW`, `TpCallbackDetectedUnrecoverableError`, `TpCallbackSendAlpcMessageOnCompletion`, `TpCallbackSendPendingAlpcMessage`, `TpDbgDumpHeapUsage`, `TpDbgSetLogRoutine`, `WerReportExceptionWorker`, `WerReportSQMEvent`, `ZwApphelpCacheControl`, `ZwCallEnclave`, `ZwCallbackReturn`, `ZwContinue`, `ZwContinueEx`, `ZwCreatePagingFile`, `ZwDirectGraphicsCall`, `ZwDisplayString`, `ZwDrawText`, `ZwFlushInstallUILanguage`, `ZwFlushProcessWriteBuffers`, `ZwFreeUserPhysicalPages`, `ZwFreezeRegistry`, `ZwFreezeTransactions`, `ZwGetDevicePowerState`, `ZwGetNotificationResourceManager`, `ZwInitializeEnclave`, `ZwInitializeNlsFiles`, `ZwInitializeRegistry`, `ZwInitiatePowerAction`, `ZwLoadDriver`, `ZwLoadEnclaveData`, `ZwLoadKey`, `ZwLoadKey2`, `ZwLoadKey3`, `ZwLoadKeyEx`, `ZwLockProductActivationKeys`, `ZwLockRegistryKey`, `ZwManageHotPatch`, `ZwManagePartition`, `ZwMapCMFModule`, `ZwMapUserPhysicalPages`, `ZwMapUserPhysicalPagesScatter`, `ZwModifyBootEntry`, `ZwModifyDriverEntry`, `ZwNotifyChangeSession`, `ZwPlugPlayControl`, `ZwPrePrepareComplete`, `ZwPrePrepareEnlistment`, `ZwPrepareComplete`, `ZwPrepareEnlistment`, `ZwPrivilegeObjectAuditAlarm`, `ZwPrivilegedServiceAuditAlarm`, `ZwPropagationComplete`, `ZwPropagationFailed`, `ZwRaiseHardError`, `ZwSetBootEntryOrder`, `ZwSetBootOptions`, `ZwSetSystemPowerState`, `ZwWaitForWorkViaWorkerFactory`, `__C_specific_handler`, `__misaligned_access`, `_fltused`, `_local_unwind`

## Untested (remaining gaps)

267 exports have neither a test nor a recorded reason; the full list is the difference of `tools/uncovered.txt` and `tools/uncovered_justified.txt`.

## Limits

- Static candidates are not proof of executed, asserted, deep or correct behavior; depth on already-covered exports (error paths, boundaries, races) is ongoing work.
- Destructive and special-setup tests are not part of this corpus yet (SOW section 5: needs an opt-in area).
- Only build 19045 was available as a baseline; other Windows 10 builds, locales and SKUs are unverified.
- Ordinal-only export 8 is never invoked.

Regenerate: `python3 tools/coverage.py --preprocess`, run all areas on a Windows 10 guest (administrator and standard user), then `python3 tools/write_coverage_win10.py --adm <dir> --std <dir>`.
