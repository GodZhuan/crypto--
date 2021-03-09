#include<ios>
#include<fstream>
#ifndef _FILE_PROC_H_
#define _FILE_PROC_H_
namespace crypto__ {
	class FileProc
	{
	public:
		FileProc(std::string fin,  std::string fout) :in(fin, std::ios::binary), out(fout, std::ios::binary | std::ios::ate) {}
		~FileProc() {
			in.close();
			out.close();
		}
		std::streamsize read(char* buf, size_t cnt) {
			in.read(buf, cnt);
			/*std::streamsize n = cnt - in.gcount();
			if (n)*/
			return in.gcount();
		}
		void write(const char* buf, size_t cnt) {
			out.write(buf, cnt);
		}
	private:
		std::ifstream in;
		std::ofstream out;
	};
}

#endif // !_FILE_PROC_H_
