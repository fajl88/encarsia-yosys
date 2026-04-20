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

#include "kernel/register.h"
#include "kernel/log.h"

#include "kernel/celltypes.h"
#include "kernel/consteval.h"
#include "kernel/sigtools.h"
#include "kernel/satgen.h"
#include <stdlib.h>
#include <stdio.h>
#include <algorithm>
#include <errno.h>
#include <fstream>
#include <string.h>
#include "selection.h"
#include "inject_utils.h"
#include <chrono>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

static std::string get_time(){
	auto now = std::chrono::system_clock::now();
	auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
	std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
	char buf[100];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now_time_t));

	return std::string(buf)+"."+std::to_string(milliseconds.count());
}

struct VerifyMiterPass : public Pass {
	VerifyMiterPass() : Pass("verify_miter", "verify signal mix-up bugs") { }
	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
	}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		auto run_start = std::chrono::steady_clock::now();
		std::vector<std::pair<std::string, std::string>> sets, sets_init;
		std::map<int, std::vector<std::pair<std::string, std::string>>> sets_at;
		std::map<int, std::vector<std::string>> unsets_at;
		std::vector<std::string> shows;
		int max_sensitization = 20, max_propagation = 32, initsteps = 0, timeout = 0, stepsize = 1;
		int cegar_max_refinements = 4;
		bool set_init_zero = false, show_inputs = false, show_outputs = false;
		bool sensitized = false, propagated = false;
		bool timeout_in_sensitization = false, timeout_in_propagation = false;
		bool cegar_spurious_exhausted = false;
		std::string failure_phase = "none";
		std::string propagation_method = "bmc";
		std::string cegar_relaxation_level = "medium";
		int sensitization_step_found = -1, propagation_step_found = -1;
		int sensitization_attempts = 0, propagation_attempts = 0;
		int cegar_rounds = 0, spurious_counterexamples = 0;
		long long sensitization_time_ms = 0, propagation_time_ms = 0;
		long long preprocess_time_ms = 0;

		log_header(design, "Executing VerifyMiterPass pass.\n");

		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "-timeout" && argidx+1 < args.size()) {
				timeout = atoi(args[++argidx].c_str());
				continue;
			}
			if (args[argidx] == "-max-sensitization" && argidx+1 < args.size()) {
				max_sensitization = atoi(args[++argidx].c_str());
				continue;
			}
			if (args[argidx] == "-max-propagation" && argidx+1 < args.size()) {
				max_propagation = atoi(args[++argidx].c_str());
				continue;
			}
			if (args[argidx] == "-propagation-method" && argidx+1 < args.size()) {
				propagation_method = args[++argidx];
				continue;
			}
			if (args[argidx] == "-cegar-max-refinements" && argidx+1 < args.size()) {
				cegar_max_refinements = atoi(args[++argidx].c_str());
				continue;
			}
			if (args[argidx] == "-cegar-relaxation-level" && argidx+1 < args.size()) {
				cegar_relaxation_level = args[++argidx];
				continue;
			}
			if (args[argidx] == "-initsteps" && argidx+1 < args.size()) {
				initsteps = atoi(args[++argidx].c_str());
				continue;
			}
			if (args[argidx] == "-stepsize" && argidx+1 < args.size()) {
				stepsize = max(1, atoi(args[++argidx].c_str()));
				continue;
			}
			if (args[argidx] == "-set" && argidx+2 < args.size()) {
				std::string lhs = args[++argidx];
				std::string rhs = args[++argidx];
				sets.push_back(std::pair<std::string, std::string>(lhs, rhs));
				continue;
			}
			if (args[argidx] == "-set-at" && argidx+3 < args.size()) {
				int timestep = atoi(args[++argidx].c_str());
				std::string lhs = args[++argidx];
				std::string rhs = args[++argidx];
				sets_at[timestep].push_back(std::pair<std::string, std::string>(lhs, rhs));
				continue;
			}
			if (args[argidx] == "-unset-at" && argidx+2 < args.size()) {
				int timestep = atoi(args[++argidx].c_str());
				unsets_at[timestep].push_back(args[++argidx]);
				continue;
			}
			if (args[argidx] == "-set-init" && argidx+2 < args.size()) {
				std::string lhs = args[++argidx];
				std::string rhs = args[++argidx];
				sets_init.push_back(std::pair<std::string, std::string>(lhs, rhs));
				continue;
			}
			if (args[argidx] == "-set-init-zero") {
				set_init_zero = true;
				continue;
			}
			if (args[argidx] == "-show" && argidx+1 < args.size()) {
				shows.push_back(args[++argidx]);
				continue;
			}
			if (args[argidx] == "-show-inputs") {
				show_inputs = true;
				continue;
			}
			if (args[argidx] == "-show-outputs") {
				show_outputs = true;
				continue;
			}
		}
		if (propagation_method != "bmc" && propagation_method != "cegar_relaxed")
			log_cmd_error("Unsupported -propagation-method value '%s'.\n", propagation_method.c_str());
		if (cegar_relaxation_level != "light" && cegar_relaxation_level != "medium" && cegar_relaxation_level != "aggressive")
			log_cmd_error("Unsupported -cegar-relaxation-level value '%s'.\n", cegar_relaxation_level.c_str());
		if (cegar_max_refinements < 0)
			log_cmd_error("-cegar-max-refinements must be non-negative.\n");

		Pass::call(design, "memory_map");
		Pass::call(design, "opt -full");
		Pass::call(design, "clk2fflogic");
		Pass::call(design, "opt -full -fine");
		preprocess_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - run_start).count();


    RTLIL::Module *miter_module = design->module("\\miter");

		shows.clear();
		if (show_inputs) {
			for (auto &it : miter_module->wires_)
				if (it.second->port_input)
					shows.push_back(it.second->name.str());
		}
		if (show_outputs) {
			for (auto &it : miter_module->wires_)
				if (it.second->port_output)
					shows.push_back(it.second->name.str());
		}

		auto make_sathelper = [&]() {
			SatHelper helper(design, miter_module, false, false);
			helper.sets = sets;
			helper.sets_at = sets_at;
			helper.unsets_at = unsets_at;
			helper.shows = shows;
			helper.timeout = timeout;
			helper.sets_init = sets_init;
			helper.set_init_zero = set_init_zero;
			return helper;
		};

        RTLIL::Wire *host_output_port = miter_module->wire("\\host_output");
        if (!host_output_port) log_cmd_error("Host output port is missing!\n");
        RTLIL::Wire *reference_output_port = miter_module->wire("\\reference_output");
        if (!reference_output_port) log_cmd_error("Reference output port is missing!\n");
        RTLIL::SigSpec host_output(host_output_port), reference_output(reference_output_port);
        if (host_output.size() != reference_output.size())
            log_cmd_error("Output expression with different lhs and rhs sizes.\n");

        RTLIL::Wire *host_observables_port = miter_module->wire("\\host_observables");
        if (!host_observables_port) log_cmd_error("Host observables port is missing!\n");
        RTLIL::Wire *reference_observables_port = miter_module->wire("\\reference_observables");
        if (!reference_observables_port) log_cmd_error("Reference observables port is missing!\n");
        RTLIL::SigSpec host_observables(host_observables_port), reference_observables(reference_observables_port);
        if (host_observables.size() != reference_observables.size())
            log_cmd_error("Observables expression with different lhs and rhs sizes.\n");

		log("Sensitizing the bug!\n");
		log("time: %s\n", get_time().c_str());
		log_flush();
		auto sensitization_start = std::chrono::steady_clock::now();
		bool done_with_sensitization = false;
		std::vector<ezSAT::expression> sensitization_model_expressions;
		std::vector<bool> sensitization_model_values;
        for(int sensitization_step = 1; sensitization_step <= max_sensitization; sensitization_step++){
			++sensitization_attempts;
			auto sathelper = make_sathelper();
            sathelper.setup(sensitization_step, sensitization_step == 1);
            sathelper.generate_model();
            log_flush();

            // TODO maybe implement steps of size > 1

            if (sathelper.solve(sathelper.ez->NOT(sathelper.satgen.signals_eq(host_output, reference_output, sensitization_step)))){
				sensitized = true;
				sensitization_step_found = sensitization_step;
				sensitization_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - sensitization_start).count();

                log("Sensitized the bug.\n");
				log("time: %s\n", get_time().c_str());
				log_flush();
                sathelper.print_model();
                log_flush();
				sensitization_model_expressions = sathelper.modelExpressions;
				sensitization_model_values = sathelper.modelValues;

				auto apply_sensitization_assumptions = [&](SatHelper &helper, size_t keep_count) {
					size_t max_assumptions = std::min(keep_count, sensitization_model_expressions.size());
					for (size_t i = 0; i < max_assumptions; i++)
						helper.ez->assume(sensitization_model_values.at(i) ? sensitization_model_expressions.at(i) : helper.ez->NOT(sensitization_model_expressions.at(i)));
				};

				size_t full_assumption_count = sensitization_model_expressions.size();
				size_t initial_relaxed_assumptions = full_assumption_count;
				if (propagation_method == "cegar_relaxed") {
					if (cegar_relaxation_level == "light")
						initial_relaxed_assumptions = full_assumption_count * 3 / 4;
					else if (cegar_relaxation_level == "medium")
						initial_relaxed_assumptions = full_assumption_count / 2;
					else
						initial_relaxed_assumptions = full_assumption_count / 4;
					if (full_assumption_count > 0 && initial_relaxed_assumptions == 0)
						initial_relaxed_assumptions = 1;
				}

				auto propagation_start = std::chrono::steady_clock::now();
				for (int propagation_step = sensitization_step + 1; propagation_step <= max_propagation; ++propagation_step) {
					if (propagation_method == "bmc") {
						++propagation_attempts;
						auto propagation_helper = make_sathelper();
						propagation_helper.setup(propagation_step, propagation_step == 1);
						propagation_helper.generate_model();
						apply_sensitization_assumptions(propagation_helper, full_assumption_count);
						log_flush();

						if (propagation_helper.solve(propagation_helper.ez->NOT(propagation_helper.satgen.signals_eq(host_observables, reference_observables, propagation_step)))) {
							propagated = true;
							propagation_step_found = propagation_step;
							log("Propagated the bug.\n");
							log("time: %s\n", get_time().c_str());
							log_flush();
							propagation_helper.print_model();
							log_flush();
							break;
						} else if (propagation_helper.gotTimeout) {
							timeout_in_propagation = true;
							log("Timed out.\n");
							log("time: %s\n", get_time().c_str());
							log_flush();
							break;
						}
						continue;
					}

					size_t relaxed_assumption_count = initial_relaxed_assumptions;
					bool stop_this_step = false;
					for (int refinement_round = 0; refinement_round <= cegar_max_refinements; ++refinement_round) {
						++propagation_attempts;
						++cegar_rounds;
						auto relaxed_helper = make_sathelper();
						relaxed_helper.setup(propagation_step, propagation_step == 1);
						relaxed_helper.generate_model();
						apply_sensitization_assumptions(relaxed_helper, relaxed_assumption_count);
						log_flush();

						if (relaxed_helper.solve(relaxed_helper.ez->NOT(relaxed_helper.satgen.signals_eq(host_observables, reference_observables, propagation_step)))) {
							apply_sensitization_assumptions(relaxed_helper, full_assumption_count);
							if (relaxed_helper.solve(relaxed_helper.ez->NOT(relaxed_helper.satgen.signals_eq(host_observables, reference_observables, propagation_step)))) {
								propagated = true;
								propagation_step_found = propagation_step;
								log("Propagated the bug.\n");
								log("time: %s\n", get_time().c_str());
								log_flush();
								relaxed_helper.print_model();
								log_flush();
								stop_this_step = true;
								break;
							}
							if (relaxed_helper.gotTimeout) {
								timeout_in_propagation = true;
								log("Timed out.\n");
								log("time: %s\n", get_time().c_str());
								log_flush();
								stop_this_step = true;
								break;
							}

							++spurious_counterexamples;
							if (refinement_round >= cegar_max_refinements || relaxed_assumption_count >= full_assumption_count) {
								cegar_spurious_exhausted = true;
								stop_this_step = true;
								break;
							}
							size_t increments_left = std::max(1, cegar_max_refinements - refinement_round);
							size_t remaining = full_assumption_count > relaxed_assumption_count ? full_assumption_count - relaxed_assumption_count : 0;
							size_t increment = std::max<size_t>(1, remaining / increments_left);
							relaxed_assumption_count = std::min(full_assumption_count, relaxed_assumption_count + increment);
							continue;
						}

						if (relaxed_helper.gotTimeout) {
							timeout_in_propagation = true;
							log("Timed out.\n");
							log("time: %s\n", get_time().c_str());
							log_flush();
							stop_this_step = true;
							break;
						}
						break;
					}
					if (propagated || timeout_in_propagation || stop_this_step)
						break;
				}
				propagation_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - propagation_start).count();
				done_with_sensitization = true;
            } else if (sathelper.gotTimeout) {
				timeout_in_sensitization = true;
                log("Timed out.\n");
				log("time: %s\n", get_time().c_str());
                log_flush();
				sensitization_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - sensitization_start).count();
                break;
            } else if (sensitization_step == max_sensitization) {
                log("Failed to sensitize the bug.\n");
				log("time: %s\n", get_time().c_str());
				log_flush();
				sensitization_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - sensitization_start).count();
            }
			if (done_with_sensitization)
				break;
        }

		if (timeout_in_sensitization) failure_phase = "sensitization_timeout";
		else if (!sensitized) failure_phase = "sensitization_unsat";
		else if (propagated && propagation_method == "cegar_relaxed") failure_phase = "propagation_cegar_success";
		else if (timeout_in_propagation) failure_phase = propagation_method == "cegar_relaxed" ? "propagation_cegar_timeout" : "propagation_timeout";
		else if (cegar_spurious_exhausted) failure_phase = "propagation_cegar_spurious_exhausted";
		else if (!propagated) failure_phase = propagation_method == "cegar_relaxed" ? "propagation_cegar_unsat" : "propagation_unsat";

		long long total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - run_start).count();

		std::ofstream summary_file("verification_summary.json");
		if (summary_file.is_open()) {
			summary_file << "{\n";
			summary_file << "  \"pass\": \"verify_miter\",\n";
			summary_file << "  \"timestamp\": \"" << json_escape(get_time()) << "\",\n";
			summary_file << "  \"propagation_method\": \"" << propagation_method << "\",\n";
			summary_file << "  \"result\": {\n";
			summary_file << "    \"sensitized\": " << (sensitized ? "true" : "false") << ",\n";
			summary_file << "    \"propagated\": " << (propagated ? "true" : "false") << ",\n";
			summary_file << "    \"failure_phase\": \"" << failure_phase << "\",\n";
			summary_file << "    \"timeout_in_sensitization\": " << (timeout_in_sensitization ? "true" : "false") << ",\n";
			summary_file << "    \"timeout_in_propagation\": " << (timeout_in_propagation ? "true" : "false") << ",\n";
			summary_file << "    \"sensitization_step_found\": " << sensitization_step_found << ",\n";
			summary_file << "    \"propagation_step_found\": " << propagation_step_found << "\n";
			summary_file << "  },\n";
			summary_file << "  \"timing_ms\": {\n";
			summary_file << "    \"preprocess\": " << preprocess_time_ms << ",\n";
			summary_file << "    \"sensitization\": " << sensitization_time_ms << ",\n";
			summary_file << "    \"propagation\": " << propagation_time_ms << ",\n";
			summary_file << "    \"total\": " << total_time_ms << "\n";
			summary_file << "  },\n";
			summary_file << "  \"attempts\": {\n";
			summary_file << "    \"sensitization\": " << sensitization_attempts << ",\n";
			summary_file << "    \"propagation\": " << propagation_attempts << "\n";
			summary_file << "  },\n";
			summary_file << "  \"cegar\": {\n";
			summary_file << "    \"max_refinements\": " << cegar_max_refinements << ",\n";
			summary_file << "    \"relaxation_level\": \"" << cegar_relaxation_level << "\",\n";
			summary_file << "    \"rounds\": " << cegar_rounds << ",\n";
			summary_file << "    \"spurious_counterexamples\": " << spurious_counterexamples << "\n";
			summary_file << "  }\n";
			summary_file << "}\n";
		}
	}
} VerifyMiterPass;

PRIVATE_NAMESPACE_END