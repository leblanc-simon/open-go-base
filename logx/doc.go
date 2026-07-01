// Package logx fournit un logger structuré préconfiguré (log/slog de la stdlib)
// à partir d'un fragment de configuration appconf.Logging.
//
// New retourne un *slog.Logger écrivant sur os.Stderr ; NewWith permet de
// rediriger la sortie. Le format (text ou json), le niveau et l'ajout de la
// source (fichier:ligne) sont pilotés par la configuration. Un niveau inconnu
// retombe sur info : la construction du logger ne peut jamais échouer.
//
//	logger := logx.New(cfg.Log)
//	logger.Info("server started", "port", 8080)
package logx
