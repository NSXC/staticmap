use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Instruction, Code, Register, OpKind};
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use rayon::prelude::*;
use ahash::{AHashMap, AHashSet};
use memmap2::Mmap;

const MIN_FUNCTION_SIZE: usize = 1; // Minimum size for a valid function
const MAX_INSTRUCTION_LENGTH: usize = 1; // Maximum x86-64 instruction length

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path_to_executable>", args[0]);
        std::process::exit(1);
    }

    let path = Path::new(&args[1]);
    let file = File::open(path)?;
    let buffer = unsafe { Mmap::map(&file)? };
    let pe = PE::parse(&buffer)?;

    println!("Analyzing PE file: {:?}", path);

    let m = MultiProgress::new();
    let pb_strings = m.add(ProgressBar::new(buffer.len() as u64));
    let pb_refs = m.add(ProgressBar::new(buffer.len() as u64));

    pb_strings.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
        .unwrap()
        .progress_chars("#>-"));
    pb_refs.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
        .unwrap()
        .progress_chars("#>-"));

    let start_time = Instant::now();

    pb_strings.set_message("Extracting strings...");
    let strings = extract_strings(&buffer, &pb_strings);
    pb_strings.finish_with_message("Strings extracted");

    pb_refs.set_message("Finding string references...");
    let string_refs = find_string_references(&pe, &buffer, &strings, &pb_refs);
    pb_refs.finish_with_message("String references found");

    m.clear()?;

    let output_path = path.with_extension("txt");
    let mut output_file = File::create(&output_path)?;
    write_analysis(&pe, &buffer, &string_refs, &mut output_file)?;

    let duration = start_time.elapsed();
    println!("Analysis completed in {:.2} seconds", duration.as_secs_f64());
    println!("Results written to {:?}", output_path);

    Ok(())
}

fn extractstrings(buffer: &[u8], pb: &ProgressBar) -> AHashMap<u64, Arc<String>> {
    let chunk_size = 1024 * 1024; // 1MB chunks
    let chunks = buffer.par_chunks(chunk_size);
    let strings: Vec<_> = chunks
        .enumerate()
        .flat_map(|(chunk_index, chunk)| {
            let mut local_strings = Vec::new();
            let mut i = 0;

            while i < chunk.len() {
                if chunk[i].is_ascii() && !chunk[i].is_ascii_control() {
                    let start = i;
                    while i < chunk.len() && chunk[i] != 0 && (chunk[i].is_ascii_graphic() || chunk[i].is_ascii_whitespace()) {
                        i += 1;
                    }
                    if i - start >= 4 { 
                        let s = String::from_utf8_lossy(&chunk[start..i]).into_owned();
                        if is_meaningful_string(&s) {
                            local_strings.push(((chunk_index * chunk_size + start) as u64, Arc::new(s)));
                        }
                    }
                }
                i += 1;
            }

            pb.inc(chunk.len() as u64);
            local_strings
        })
        .collect();

    strings.into_iter().collect()
}

fn ismeaningfulstring(s: &str) -> bool {
    let meaningful_chars = s.chars().filter(|c| c.is_alphanumeric() || c.is_whitespace() || ".,;:!?-_".contains(*c)).count();
    let total_chars = s.chars().count();
    
    meaningful_chars as f32 / total_chars as f32 >= 0.2 //changeable
}

fn findstringreferences(pe: &PE, buffer: &[u8], strings: &AHashMap<u64, Arc<String>>, pb: &ProgressBar) -> AHashMap<u64, (String, AHashSet<Arc<String>>)> {
    let string_addrs: AHashSet<_> = strings.keys().cloned().collect();
    
    pe.sections
        .par_iter()
        .filter(|section| section.characteristics & 0x20 != 0) // Only analyze executable sections
        .flat_map(|section| {
            let start = section.pointer_to_raw_data as usize;
            let end = (start + section.size_of_raw_data as usize).min(buffer.len());
            let code = &buffer[start..end];

            let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
            decoder.set_ip(section.virtual_address as u64);

            let mut instruction = Instruction::default();
            let mut local_refs = Vec::new();

            let section_name = String::from_utf8_lossy(&section.name).into_owned();

            while decoder.can_decode() {
                decoder.decode_out(&mut instruction);

                let ip = instruction.ip();

                for i in 0..instruction.op_count() {
                    let target = match instruction.op_kind(i) {
                        OpKind::Memory => {
                            let base = instruction.memory_base();
                            if base == Register::RIP {
                                let disp = instruction.memory_displacement64();
                                ip.wrapping_add(instruction.len() as u64).wrapping_add(disp)
                            } else {
                                continue;
                            }
                        }
                        OpKind::Immediate32 | OpKind::Immediate64 => instruction.immediate(i),
                        _ => continue,
                    };

                    if string_addrs.contains(&target) {
                        if let Some(s) = strings.get(&target) {
                            local_refs.push((ip, section_name.clone(), Arc::clone(s)));
                        }
                    }
                }

                pb.inc(instruction.len() as u64);
            }

            local_refs
        })
        .fold(
            || AHashMap::new(),
            |mut acc: AHashMap<u64, (String, AHashSet<Arc<String>>)>, (ip, section_name, s)| {
                acc.entry(ip)
                    .or_insert_with(|| (section_name.clone(), AHashSet::new()))
                    .1
                    .insert(s);
                acc
            },
        )
        .reduce(
            || AHashMap::new(),
            |mut acc, local_refs| {
                for (ip, (section_name, refs)) in local_refs {
                    acc.entry(ip)
                        .or_insert_with(|| (section_name.clone(), AHashSet::new()))
                        .1
                        .extend(refs);
                }
                acc
            },
        )
}

fn writeanalysis(pe: &PE, buffer: &[u8], string_refs: &AHashMap<u64, (String, AHashSet<Arc<String>>)>, output: &mut impl Write) -> std::io::Result<()> {
    writeln!(output, "{:<16} {:<20} {:<50} {}", "RVA", "Section", "Instruction", "String Reference")?;
    writeln!(output, "{}", "-".repeat(120))?;

    for section in pe.sections.iter().filter(|s| s.characteristics & 0x20 != 0) {
        let start = section.pointer_to_raw_data as usize;
        let end = (start + section.size_of_raw_data as usize).min(buffer.len());
        let code = &buffer[start..end];

        let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
        decoder.set_ip(section.virtual_address as u64);

        let mut instruction = Instruction::default();
        let mut current_function_start = 0;
        let mut function_string_refs = Vec::new();
        let mut function_size = 0;

        while decoder.can_decode() {
            let offset = decoder.position();
            decoder.decode_out(&mut instruction);

            if is_function_start(&instruction) {
                if !function_string_refs.is_empty() && function_size >= MIN_FUNCTION_SIZE {
                    writeln!(output, "Function at RVA 0x{:X}:", current_function_start)?;
                    for (rva, section_name, instr, refs) in function_string_refs.drain(..) {
                        write!(output, "{:<16X} {:<20} {:<50}", rva, section_name, instr)?;
                        for s in refs {
                            write!(output, "\"{}\" ", remove_null_bytes(&s))?;
                        }
                        writeln!(output)?;
                    }
                    writeln!(output)?;
                }
                current_function_start = instruction.ip();
                function_size = 0;
            }

            if let Some((section_name, refs)) = string_refs.get(&instruction.ip()) {
                function_string_refs.push((instruction.ip(), section_name.clone(), instruction.to_string(), refs.clone()));
            }

            function_size += instruction.len();

            if offset >= code.len() - MAX_INSTRUCTION_LENGTH {
                break;
            }
        }

        if !function_string_refs.is_empty() && function_size >= MIN_FUNCTION_SIZE {
            writeln!(output, "Function at RVA 0x{:X}:", current_function_start)?;
            for (rva, section_name, instr, refs) in function_string_refs {
                write!(output, "{:<16X} {:<20} {:<50}", rva, section_name, instr)?;
                for s in refs {
                    write!(output, "\"{}\" ", remove_null_bytes(&s))?;
                }
                writeln!(output)?;
            }
        }
    }

    Ok(())
}

fn isfunctionstart(instruction: &Instruction) -> bool {
    matches!(
        instruction.code(),
        Code::Push_r64 | Code::Sub_rm64_imm8 | Code::Mov_rm64_r64
    ) && matches!(
        instruction.op0_register(),
        Register::RBP | Register::RSP
    )
}

fn removenullbytes(s: &Arc<String>) -> String {
    s.chars().filter(|&c| c != '\0').collect()
}

