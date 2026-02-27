package appconfig

import (
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// configureKubernetes returns both rest.Config and typed clientset.
func configureKubernetes(local bool) (*rest.Config, *kubernetes.Clientset, error) {
	kubeCfg, err := configureKubernetesConfig(local)
	if err != nil {
		return nil, nil, err
	}

	clientset, err := kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		return nil, nil, err
	}

	return kubeCfg, clientset, nil
}

func configureKubernetesConfig(local bool) (*rest.Config, error) {
	if local {
		kubeCfg, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
		if err != nil {
			return nil, err
		}

		return kubeCfg, nil
	}

	kubeCfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	return kubeCfg, nil
}
