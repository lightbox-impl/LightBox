#include "Enclave_u.h"

#include <stdlib.h>
void ocall_malloc(void** pointer, int size)
{
	*pointer = malloc(size);
}
void ocall_free(void* pointer)
{
	if(pointer)
		free(pointer);
	pointer = 0;
}
void ocall_del(void* pointer, int isArray)
{
	if (pointer)
	{
		if (isArray)
		{
			delete[] pointer;

		}
		else
		{
			delete pointer;
		}
	}
	pointer = 0;
}

#include <stdio.h>
void ocall_print_string2(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	* the input string to prevent buffer overflow.
	*/
	printf("%s", str);
}



#include <ctime>
void ocall_get_time2(int *second, int *nanosecond)
{
	timespec wall_clock;
	clock_gettime(CLOCK_REALTIME, &wall_clock);
	memcpy(second, &wall_clock.tv_sec, sizeof(wall_clock.tv_sec));
	memcpy(nanosecond, &wall_clock.tv_nsec, sizeof(wall_clock.tv_nsec));
	//*second = wall_clock.tv_sec;
	//*nanosecond = wall_clock.tv_nsec;
	//
	//printf("ocall get time size %d:%d\n", sizeof(wall_clock.tv_sec), sizeof(wall_clock.tv_nsec));
	//printf("ocall now is %lds, %ldns.\n", wall_clock.tv_sec, wall_clock.tv_nsec);
}


#include <random>
void ocall_rand(int *rand_num, int mod)
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<int> dis(0, mod-1);

	*rand_num = dis(gen);
}

#include <cstring>
void ocall_get_data(int data_id, char** val, int* len)
{
	switch (data_id)
	{
	case 1:
	{
		int str_len = 20;
		char* str = new char[str_len];
		memcpy(str, "data1: hello world.", str_len);
		*val = str;
		*len = str_len;
		break;
	}
	default:
	{
		*val = 0;
		*len = 0;
		break;
	}
	}
}


#include <sys/stat.h> 
void ocall_file_size(char* filePath, int* len)
{
	struct stat s_buf;
	// get path info
	stat(filePath, &s_buf);
	
	*len = s_buf.st_size;
}

#include <dirent.h> 
#include <string>
#include <vector>
using std::vector;
using std::string;

static void dir_oper(char const*path, vector<string>& files, bool recursion);

static bool dir_files(char const*path, vector<string>& files, bool recursion)
{
	struct stat s_buf;

	// get path info
	stat(path, &s_buf);
	// if path is dir, then open it
	if (S_ISDIR(s_buf.st_mode))
	{
		dir_oper(path, files, recursion);
		return true;
	}
	// or the path is a file, then output it 
	else if (S_ISREG(s_buf.st_mode))
	{
		return false;
	}
}

static void dir_oper(char const*path, vector<string>& files, bool recursion)
{
	// output dir paht
	struct dirent *filename;
	struct stat s_buf;

	// get DIR object
	DIR *dp = opendir(path);

	// read all files
	while (filename = readdir(dp))
	{
		// piece the full file path
		char file_path[200];
		bzero(file_path, 200);
		strcat(file_path, path);
		strcat(file_path, "/");
		strcat(file_path, filename->d_name);

		// except . and ..
		if (strcmp(filename->d_name, ".") == 0 || strcmp(filename->d_name, "..") == 0)
		{
			continue;
		}

		// use the full path to get stat
		stat(file_path, &s_buf);

		// if it is a dir, then loop self
		if (S_ISDIR(s_buf.st_mode))
		{
			if (recursion)
			{
				dir_oper(file_path, files, recursion);
			}
			//printf("\n");
		}

		// if it is a file 
		if (S_ISREG(s_buf.st_mode))
		{
			files.push_back(file_path);
			//printf("[%s] is a regular file\n", file_path);
		}
	}
}

void ocall_read_dir(char* dirPaht, char** allFiles, int* fileCount, int subfile)
{
	const int EACH_FILE_NAME_BUFFER_SIZE = 256;
	vector<string> child_files;
	if (dir_files(dirPaht, child_files, subfile!=0))
	{
		*fileCount = child_files.size();
		*allFiles = new char[EACH_FILE_NAME_BUFFER_SIZE**fileCount];
		for (int i = 0; i < *fileCount; i++)
		{
			strncpy(*allFiles + i* EACH_FILE_NAME_BUFFER_SIZE, child_files.at(i).c_str(), EACH_FILE_NAME_BUFFER_SIZE);
		}
	}
}

#include <fstream>
void ocall_read_file(char* filePath, char** out, int* len, int pos)
{
	int fileSize;
	ocall_file_size(filePath, &fileSize);

	std::ifstream fin;
	try
	{
		fin.open(filePath, std::ios::in | std::ios::binary);

		if (fin.good())
		{
			if (pos > 0)
			{
				fin.seekg(pos);
			}
			else
			{
				pos = 0;
			}

			*out = (char*)malloc(fileSize);
			
			*len = (*len < 1 || *len >(fileSize - pos) ? (fileSize - pos) : (*len));
			fin.read(*out, *len);
		}
		else
		{
			printf("file %s open failed.\n", filePath);
			*out = 0;
			*len = -1;
		}
	}
	catch(...)
	{
		fin.close();
	}

	fin.close();
}

#define fast_app_write
#ifdef fast_app_write
void ocall_write_file(char* filePath, char* src, int len, int append)
{
	static std::ofstream fout;
	try
	{
		if (!fout.is_open())
		{
			fout.open(filePath, std::ios::out | std::ios::binary | (append == 0 ? std::ios::trunc : std::ios::app));
		}

		if (fout.good())
		{
			fout.write(src, len);
			fout.flush();
		}
		else
		{
			printf("file %s open failed.\n", filePath);
		}
	}
	catch (...)
	{
		//fout.close();
	}
	//fout.close();
}
#else
void ocall_write_file(char* filePath, char* src, int len, int append)
{
	std::ofstream fout;

	try
	{
		//printf("append is :%d\n", append);
		fout.open(filePath, std::ios::out | std::ios::binary | (append == 0 ? std::ios::trunc : std::ios::app));

		if (fout.good())
		{
			fout.write(src, len);
		}
		else
		{
			printf("file %s open failed.\n", filePath);
		}
	}
	catch (...)
	{
		fout.close();
	}
	fout.close();
}
#endif


#include "dfc/pattern_loader.h"

void ocall_dfc_init(char** out_pattern_pool, int **out_pattern_length, int* out_size)
{
	const char pattern_file[] = "./snort.pat";
	unsigned char* pattern_pool = 0;
	int *pattern_len = 0;
	int pattern_pool_size = PatternLoader::load_pattern_file(pattern_file, pattern_pool, pattern_len);

	*out_size = pattern_pool_size;
	*out_pattern_pool = (char*)pattern_pool;
	*out_pattern_length = pattern_len;
}