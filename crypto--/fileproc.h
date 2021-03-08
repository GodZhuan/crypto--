#include <fstream>
#ifndef _FILE_PROC_H_
#define _FILE_PROC_H_
class FileProc
{
public:
	FileProc();
	template<typename T1,typename T2,typename T3>
	FileProc(T1 fin, T2 k, T3 fout) :in(fin), key(k), out(fout) {}
	template<typename T1, typename T2>
	FileProc(T1 fin, T2 k) : in(fin), key(k) {
		
	}
	~FileProc();

private:
	std::ifstream in;
	std::ofstream out;
	std::string key;
};

FileProc::FileProc()
{
}

FileProc::~FileProc()
{
}
#endif // !_FILE_PROC_H_
