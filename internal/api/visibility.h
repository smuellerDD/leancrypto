/*
 *  see https://gcc.gnu.org/wiki/Visibility
 *
 *  use -fvisibility=hidden to mark all symbols hidden per default
 *
 *  It is sufficient to use the macros in the declarations only. The
 *  definitions do not need to be instrumented.
 */

#ifndef VISIBILITY_H
#define VISIBILITY_H

#define DSO_PUBLIC __attribute__ ((visibility ("default")))
#define DSO_LOCAL  __attribute__ ((visibility ("hidden")))

#endif /* VISIBILITY_H */
