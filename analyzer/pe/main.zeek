module PE;

export {
    redef record PE::Info += {section_entropy: vector of string &log &optional &default=vector();};
	option default_log_section_entropy = T;

	type ExportName: record {
		rva:  count;
		name: string &optional;
	};

	type ExportAddress: record {
		rva:       count;
		forwarder: string &optional;
	};

	type ExportTable: record {
		flags:               count;
		timestamp:           time;
		major_version:       count;
		minor_version:       count;
		dll_name_rva:        count;
		ordinal_base:        count;
		address_table_count: count;
		name_table_count:    count;
		address_table_rva:   count;
		name_table_rva:      count;
		ordinal_table_rva:   count;
		dll:                 string &optional;
		addresses:           vector of ExportAddress &optional;
		names:               vector of ExportName &optional;
		ordinals:            vector of count &optional;
	};

	type Import: record {
		hint_name_rva: count &optional;
		hint:          count &optional;
		name:          string &optional;
		ordinal:       count &optional;
	};

	type ImportTableEntry: record {
		import_lookup_table_rva:  count;
		timestamp:                time;
		forwarder_chain:          count;
		dll_rva:                  count;
		import_address_table_rva: count;
		dll:                      string &optional;
		imports:                  vector of Import &optional;
	};

	type ImportTable: record {
		entries: vector of ImportTableEntry;
	};
}

event pe_section_bytes_counts(f: fa_file, cts: table[string] of table[count] of count, section_lenghts: table[string] of double) {
	# Ignore this event when we're not interested in the section entropy
	if ( ! default_log_section_entropy ) {
		return;
	}

	# A temporary table to save the intermediate results
	local tmp_table: vector of string;

	for (section, counts in cts) {
		local sectionTotalBytes: double = section_lenghts[section];
		local entropy: double = 0.0;

		# Calculate the Shannon entropy of the bits
		# https://en.wikipedia.org/wiki/Entropy_(information_theory)
		# H(X) = -sum(P_xi * log_2(xi))
		# where log2() is represented with log10(p_x)/log10(2)
		for (byte, cnt in counts) {
			local p_x: double = cnt/sectionTotalBytes;

			if (p_x > 0.0) {
				entropy = entropy - (p_x * log10(p_x)/log10(2));
			}
		}

		local entropy_string: string = fmt("%s:%f", section, entropy);

		# If the vector() is still empty, create one
		if ( | f$pe$section_entropy | == 0 ) {
			tmp_table = vector();
		} else {
			# Otherwise just set the existing table as the temporary table
			tmp_table = f$pe$section_entropy;
		}

		# Add the new entropy string of this section to the table
		tmp_table += entropy_string;

		# And set the table back to the section_entropy field
		f$pe$section_entropy = tmp_table;

		## DEBUG
		#print fmt("Entropy for section '%s': %f", section, entropy);
	}
}

module Files;

# This is a way of bypassing Zeek's automatic PE analysis using its own PE
# analyzer.  It helps prevent duplicate events on Zeek 4.0 and before, where
# there's no API to disable file analyzers and so Spicy .evt can't rely
# on the 'replaces' setting to help substitute for Zeek's builtin PE analyzer.
# This wouldn't prevent someone from manually using Zeek's builtin PE
# via Files::add_analyzer(), but it work work for most cases (also, when using
# 'replaces' someone could still end up bypassing via Files::enable_analyzer()
# and somehow end up getting duplicates if they're motivated enough).
event zeek_init() &priority=-10
	{
	local pe_tag = Files::ANALYZER_PE;

	if ( pe_tag !in Files::mime_types )
		return;

	for ( mt in Files::mime_types[pe_tag] )
		delete Files::mime_type_to_analyzers[mt][pe_tag];

	delete Files::mime_types[pe_tag];
	}
