/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package ns On Linux each OS thread can have a different network namespace.
// Go's thread scheduling model switches goroutines between OS threads based on OS thread load
// and whether the goroutine would block other goroutines. This can result in a goroutine
// switching network namespaces without notice and lead to errors in your code.
package ns

const (
	coneNewNet = 0x40000000

	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h
	nsFsMagic      = 0x6e736673
	procSuperMagic = 0x9fa0

	// SoMark mark packets sent from a specific socket.
	SoMark = 0x24
)
