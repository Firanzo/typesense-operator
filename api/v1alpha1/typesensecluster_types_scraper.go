package v1alpha1

import corev1 "k8s.io/api/core/v1"

type DocSearchScraperSpec struct {
	// Name specifies the name of the scraper. This will be used to name the corresponding Kubernetes CronJob.
	Name string `json:"name"`
	// Image specifies the Docker image to use for the DocSearch scraper.
	Image string `json:"image"`
	// Config is a JSON string containing the DocSearch configuration (e.g., index_name, start_urls, selectors).
	Config string `json:"config"`

	// Schedule defines the cron schedule on which the scraper should run (e.g., "0 0 * * *").
	// +kubebuilder:validation:Pattern:=`(^((\*\/)?([0-5]?[0-9])((\,|\-|\/)([0-5]?[0-9]))*|\*)\s+((\*\/)?((2[0-3]|1[0-9]|[0-9]|00))((\,|\-|\/)(2[0-3]|1[0-9]|[0-9]|00))*|\*)\s+((\*\/)?([1-9]|[12][0-9]|3[01])((\,|\-|\/)([1-9]|[12][0-9]|3[01]))*|\*)\s+((\*\/)?([1-9]|1[0-2])((\,|\-|\/)([1-9]|1[0-2]))*|\*|(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|des))\s+((\*\/)?[0-6]((\,|\-|\/)[0-6])*|\*|00|(sun|mon|tue|wed|thu|fri|sat))\s*$)|@(annually|yearly|monthly|weekly|daily|hourly|reboot)`
	// +kubebuilder:validation:Type=string
	Schedule string `json:"schedule"`

	// AuthConfiguration references a Kubernetes Secret containing authentication credentials (e.g., HTTP Basic Auth) required by the scraper to access the target website.
	// +kubebuilder:validation:Optional
	AuthConfiguration *corev1.LocalObjectReference `json:"authConfiguration,omitempty"`
}

func (s *DocSearchScraperSpec) GetScraperAuthConfiguration() []corev1.EnvFromSource {
	if s.AuthConfiguration != nil {
		return []corev1.EnvFromSource{
			{
				SecretRef: &corev1.SecretEnvSource{
					LocalObjectReference: *s.AuthConfiguration,
				},
			},
		}
	}

	return []corev1.EnvFromSource{}
}
