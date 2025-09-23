package appconfig

import (
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func configureKubernetesClient(local bool) (*kubernetes.Clientset, error) {
	kubernetesConfig, err := configureKubernetesConfig(local)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(kubernetesConfig)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

func configureKubernetesConfig(local bool) (*rest.Config, error) {
	if local {
		kubernetesConfig, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
		if err != nil {
			return nil, err
		}

		return kubernetesConfig, nil
	} else {
		kubernetesConfig, err := rest.InClusterConfig()
		if err != nil {
			return nil, err
		}

		return kubernetesConfig, nil
	}
}
