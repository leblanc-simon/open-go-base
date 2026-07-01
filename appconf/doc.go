// Package appconf charge la configuration d'une application depuis un fichier
// YAML ou l'environnement, et câble les flags --help / --version.
//
// Il décrit des données (Options + fragments de config réutilisables) et ne
// dépend d'aucun composant runtime : la dépendance va toujours composant ->
// appconf, jamais l'inverse.
//
// # Bootstrap
//
// Load remplit une struct de configuration depuis le fichier pointé par le flag
// -c s'il existe, sinon depuis l'environnement, en appliquant les valeurs par
// défaut (tag env-default). MustLoad fait de même mais termine en code 2 sur
// erreur. --help affiche l'usage des flags puis la documentation des variables
// d'environnement ; --version affiche "<Name> <Version>" et sort en code 0.
//
// # Fragments
//
// Web, Redis, Logging, CORS, I18n, Auth, MFA et Database sont des fragments à
// embarquer par composition dans la Config du projet. Leurs tags env sont volontairement SANS
// préfixe : le préfixe est posé au point de composition via env-prefix, car
// cleanenv ne supporte qu'un préfixe statique.
//
//	type Config struct {
//		Web appconf.Web     `yaml:"web"     env-prefix:"OGS_"`
//		Log appconf.Logging `yaml:"logging" env-prefix:"OGS_"`
//	}
package appconf
