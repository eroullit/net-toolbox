
#ifndef _NET_VERSION_H_
#define _NET_VERSION_H_

/* Versioning information */
#define PROGNAME_STRING  "netsniff-ng"
#define VERSION_STRING   "0.5.5.0"

/*
 * Some versioning definition:
 * w.x.y.z 
 * `-+-+-+-- "Huge"  changes ---> These only change on overflow of "Minor"
 *   `-+-+-- "Major" changes _/            - x elem of {0, 1, ..., 9}
 *     `-+-- "Minor" changes, new features - y elem of {0, 1, ..., 9}
 *       `-- "Tiny"  changes, bug fixes    - z elem of {0, 1, ...}
 */

#endif				/* _NET_VERSION_H_ */
