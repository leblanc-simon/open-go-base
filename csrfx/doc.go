// Package csrfx fournit un middleware de protection CSRF par double soumission
// (double-submit cookie), composable comme corsx et ratelimit.
//
// Modèle : le middleware pose un cookie de jeton aléatoire (HttpOnly, SameSite=
// Lax) sur les requêtes sûres et exige, sur les requêtes mutantes, que le même
// jeton soit présenté dans l'en-tête X-CSRF-Token ou le champ de formulaire
// csrf_token. La comparaison est en temps constant ; un échec renvoie 403.
//
// C'est une défense EN PROFONDEUR, complémentaire des cookies SameSite=Lax
// d'authx (qui restent la première barrière). Le jeton étant porté par un cookie
// non signé, le modèle suppose qu'un attaquant ne peut pas écrire ce cookie sur
// le domaine : éviter de partager un domaine parent avec des sous-domaines non
// fiables.
//
// Intégration côté projet :
//
//	p := csrfx.New()
//	mux := http.NewServeMux()
//	// ... routes ...
//	handler := p.Middleware(mux)
//
// Dans les templates, injecter le jeton via le FuncMap par requête :
//
//	tmpl.Funcs(p.FuncMap(r)).Execute(w, data) // {{ csrfField }} dans le <form>
//
// Le requêtes AJAX peuvent à la place renvoyer le jeton (csrfx.Token(r)) dans
// l'en-tête X-CSRF-Token.
package csrfx
