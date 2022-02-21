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
package options

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/merbridge/merbridge/config"
)

// NewOptions setup tasks when start up and return a kubernetes client
func NewOptions() error {
	if config.Debug {
		log.SetLevel(log.DebugLevel)
	}
	if config.Mode != config.ModeIstio && config.Mode != config.ModeLinkerd {
		return fmt.Errorf("invalid mode %q, current only support istio and linkerd", config.Mode)
	}
	return nil
}
