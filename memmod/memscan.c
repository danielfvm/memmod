#include <python3.10/Python.h>

#include <python3.10/bytesobject.h>
#include <python3.10/listobject.h>
#include <python3.10/modsupport.h>
#include <python3.10/pyport.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

typedef enum {
	MATCH,
	INSIDE,
} ScanMode;

typedef union convert {
	int64_t number;
	uint8_t bytes[8];
} convert;


uint8_t memread(int fd, int64_t address, uint8_t* bytes, size_t size) {
	lseek(fd, address, SEEK_SET);

	if (!read(fd, bytes, size)) {
		free(bytes);
		return 0;
	}

	lseek(fd, 0, SEEK_SET);

	return 1;
}

static PyObject* memscan(PyObject *self, PyObject *args) {    
	PyObject *_arg1, *_arg2, *ret;
	convert top, bottom, conv;

	int fd, type; 
	int64_t start, end, argsize, chunksize;
	char *arg1, *arg2;
	uint8_t* buffer;
	uint64_t i;

	ret = PyList_New(0);

    if (!PyArg_ParseTuple(args, "iiKKSSKK", &fd, &type, &start, &end, &_arg1, &_arg2, &argsize, &chunksize)) {
        return ret;
    }

	arg1 = PyBytes_AsString(_arg1);
	arg2 = PyBytes_AsString(_arg2);

	buffer = (uint8_t*) malloc(chunksize);

	if (type == INSIDE) {
		memset(bottom.bytes, 0, 8);
		memcpy(bottom.bytes, arg1, argsize);
		memset(top.bytes, 0, 8);
		memcpy(top.bytes, arg2, argsize);
	}

	for (int64_t adr = start; adr < end; adr += chunksize - argsize + 1) {
		int64_t size = min(chunksize, end-adr);
		if (size < argsize) break;

		memread(fd, adr, buffer, size);

		switch (type) {
		case MATCH:
			for (i = 0; i < size - argsize; ++ i) {
				if (memcmp(buffer + i, arg1, argsize) == 0) {
					PyObject* address = Py_BuildValue("K", adr + i);
					PyObject* data = PyBytes_FromStringAndSize(buffer + i, argsize);
					PyList_Append(ret, Py_BuildValue("OO", address, data));
					i += argsize-1;
				}
			}
			break;
		case INSIDE: 
			for (i = 0; i < size - argsize; ++ i) {
				memset(conv.bytes, 0, 8);
				memcpy(conv.bytes, buffer + i, argsize);
				if (bottom.number <= conv.number && conv.number < top.number) {
					PyObject* address = Py_BuildValue("K", adr + i);
					PyObject* data = PyBytes_FromStringAndSize(buffer + i, argsize);
					PyList_Append(ret, Py_BuildValue("OO", address, data));
				}
			}
			break;
		}
	}

	free(buffer);

    return ret;
}

static PyMethodDef InternalMethods[] = {
    {"memscan",  memscan, METH_VARARGS, "Scans memory for matches or addresses"},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

static struct PyModuleDef memscan_module = {
    PyModuleDef_HEAD_INIT,
    "external",
    NULL,
    -1,
    InternalMethods
};

PyMODINIT_FUNC
PyInit_memscan(void) {
    return PyModule_Create(&memscan_module);
}
