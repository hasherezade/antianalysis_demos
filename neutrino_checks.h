#pragma once

/**
Performs defensive environment check - against VM, sandbox, monitoring tools etc.
Implementation by Hasherezade, based on Neutrino Bot Loader
read more: https://blog.malwarebytes.com/threat-analysis/2017/02/new-neutrino-bot-comes-in-a-protective-loader/
*/
bool find_by_neutrino_checks(const char *log_filename = nullptr);
