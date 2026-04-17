/*
 *  yosys -- Yosys Open SYnthesis Suite
 *
 *  Copyright (C) 2024  Matej Bölcskei <mboelcskei@ethz.ch>
 *
 *  Permission to use, copy, modify, and/or distribute this software for any
 *  purpose with or without fee is hereby granted, provided that the above
 *  copyright notice and this permission notice appear in all copies.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

// TODO check whether these are actually needed
#include "kernel/register.h"
#include "kernel/log.h"

#include "kernel/celltypes.h"
#include "kernel/consteval.h"
#include "kernel/sigtools.h"
#include "kernel/satgen.h"
#include <stdlib.h>
#include <stdio.h>
#include <algorithm>
#include <numeric>
#include <unordered_map>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include "selection.h"

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

static void write_design(RTLIL::Design *design, std::string output_directory, int index){
	std::string host_directory = output_directory + "/" + std::to_string(index);
	if (mkdir(host_directory.c_str(), 0755)){
		log_error("Error creating bug directory: %s.\n", strerror(errno));
	}
	// TODO remove this call maybe
	Pass::call(design, "write_rtlil " + host_directory + "/host_amt.rtlil");
}

struct AmtBugCandidate {
	RTLIL::Cell *cell;
	std::vector<selection_t> selections;
};

static std::vector<int> compute_module_budgets(int module_count, int num_bugs)
{
	std::vector<int> budgets(module_count, 0);
	if (module_count <= 0 || num_bugs <= 0)
		return budgets;

	std::vector<int> order(module_count);
	std::iota(order.begin(), order.end(), 0);
	std::random_shuffle(order.begin(), order.end());

	if (module_count > num_bugs) {
		for (int i = 0; i < num_bugs; ++i)
			budgets[order[i]] = 1;
		return budgets;
	}

	int base = num_bugs / module_count;
	int rem = num_bugs % module_count;
	for (int i = 0; i < module_count; ++i)
		budgets[i] = base;
	for (int i = 0; i < rem; ++i)
		budgets[order[i]]++;
	return budgets;
}

struct InjectAmtPass : public Pass {
	InjectAmtPass() : Pass("inject_amt", "produce designs with buggy AMTs") { }
	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    inject_amt [options] [selection]\n");
		log("\n");
		log("This pass produces designs with buggy AMTs.\n");
		log("\n");
		log("Options:\n");
		log("\n");
		log("    -output-dir directory\n");
		log("        generated designs are stored in the directory\n");
		log("    -num-bugs number\n");
		log("        the desired number of bugs to be injected into the design\n");
		log("    -seed number\n");
		log("        seed for deterministic random bug selection\n");
	}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		std::string output_directory;
		int num_bugs = 100;
		bool seed_set = false;
		unsigned seed = 0;
		int index = 0;

		log_header(design, "Executing InjectAmt pass (producing designs with buggy AMTs).\n");

		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "-output-dir" && argidx+1 < args.size() && output_directory.empty()) {
				output_directory = args[++argidx];
				continue;
			}
			if (args[argidx] == "-num-bugs" && argidx+1 < args.size()) {
				num_bugs = atoi(args[++argidx].c_str());
				continue;
			}
			if (args[argidx] == "-seed" && argidx+1 < args.size()) {
				seed = (unsigned)strtoul(args[++argidx].c_str(), nullptr, 10);
				seed_set = true;
				continue;
			}
		}
		if (output_directory.empty()) {
			log_error("Missing mandatory argument -output-dir!\n");
		}
		if (seed_set)
			srand(seed);
		if (num_bugs < 0) {
			log_error("Argument -num-bugs must be non-negative.\n");
		}
		if (num_bugs == 0) {
			log("inject_amt: requested 0 bugs, nothing to do.\n");
			return;
		}

		std::vector<RTLIL::Module*> eligible_modules;
		std::vector<std::vector<AmtBugCandidate>> module_candidates;
		std::unordered_map<RTLIL::Cell*, std::vector<selection_t>> original_selections;

		for (auto module : design->selected_modules()) {
			std::vector<AmtBugCandidate> candidates;
			for (auto cell : module->selected_cells()) {
				if (cell->type != ID($amt))
					continue;

				std::vector<selection_t> selections;
				copy_from_cell(cell, selections);
				if (selections.size() < 4)
					continue;
				original_selections[cell] = selections;
				log_amt(cell, selections);

				for (int selection_index = 0; selection_index < GetSize(selections); ++selection_index) {
					const selection_t &selection = selections[selection_index];
					if (selection.output.is_fully_undef())
						continue;

					for (int bit_index = 0; bit_index < GetSize(selection.select.bits); ++bit_index) {
						RTLIL::State bit = selection.select.bits[bit_index];

						if (bit == RTLIL::State::S0 || bit == RTLIL::State::S1) {
							std::vector<selection_t> buggy_selections = selections;
							buggy_selections[selection_index].select.bits[bit_index] = RTLIL::State::Sa;
							buggy_selections[selection_index].buggy = true;
							candidates.push_back({cell, buggy_selections});
						} else if (bit == RTLIL::State::Sa) {
							std::vector<selection_t> buggy_zero = selections;
							buggy_zero[selection_index].select.bits[bit_index] = RTLIL::State::S0;
							buggy_zero[selection_index].buggy = true;
							candidates.push_back({cell, buggy_zero});

							std::vector<selection_t> buggy_one = selections;
							buggy_one[selection_index].select.bits[bit_index] = RTLIL::State::S1;
							buggy_one[selection_index].buggy = true;
							candidates.push_back({cell, buggy_one});
						}
					}

					if (GetSize(selections) > 1) {
						std::vector<selection_t> removed_selection = selections;
						removed_selection.erase(removed_selection.begin() + selection_index);
						candidates.push_back({cell, removed_selection});
					}
				}
			}

			if (!candidates.empty()) {
				eligible_modules.push_back(module);
				module_candidates.push_back(candidates);
			}
		}

		if (eligible_modules.empty()) {
			log_warning("inject_amt: no eligible modules found; generated 0 bugs.\n");
			return;
		}

		std::vector<int> budgets = compute_module_budgets(GetSize(eligible_modules), num_bugs);
		int generated = 0;

		for (int module_idx = 0; module_idx < GetSize(eligible_modules); ++module_idx) {
			int module_budget = budgets[module_idx];
			if (module_budget <= 0)
				continue;

			std::vector<AmtBugCandidate> &candidates = module_candidates[module_idx];
			std::vector<int> order(GetSize(candidates));
			std::iota(order.begin(), order.end(), 0);
			std::random_shuffle(order.begin(), order.end());

			int emit_count = std::min(module_budget, GetSize(candidates));
			for (int i = 0; i < emit_count; ++i) {
				AmtBugCandidate &candidate = candidates[order[i]];
				RTLIL::Cell *cell = candidate.cell;

				cell->attributes[ID(buggy)] = RTLIL::Const("buggy");
				cell->getPort(ID::Y).as_wire()->attributes[ID(buggy)] = RTLIL::Const("buggy");
				copy_to_cell(cell, candidate.selections);
				write_design(design, output_directory, ++index);
				++generated;

				copy_to_cell(cell, original_selections[cell]);
				cell->attributes.erase(ID(buggy));
				cell->getPort(ID::Y).as_wire()->attributes.erase(ID(buggy));
			}
		}

		if (generated < num_bugs) {
			log_warning("inject_amt: requested %d bugs, generated %d. Capped to available candidates.\n",
					num_bugs, generated);
		}
	}
} InjectAmtPass;

PRIVATE_NAMESPACE_END