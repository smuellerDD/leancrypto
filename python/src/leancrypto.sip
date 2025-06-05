// Define the SIP wrapper to the (actual) fib library.

%Module(name=leancrypto, language="C")

%ModuleCode
#include <leancrypto.h>
%End

void lc_status(char *outbuf, size_t outlen);
