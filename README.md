# Innloggingssystem for Server Hosting Website

## Prosjektbeskrivelse

Dette prosjektet har som mål å utvikle et sikkert innloggingssystem for en server hosting-plattform. Brukerne skal kunne logge inn med brukernavn og passord, og all brukerdata skal krypteres og lagres trygt i en database. Systemet skal implementere moderne sikkerhetsteknikker for å beskytte brukerens informasjon mot vanlige sikkerhetstrusler.

## Funksjoner

- **Brukerinnlogging:**  
  Brukerne kan logge inn med et brukernavn og passord. Passordet verifiseres mot databasen, og feilmeldinger vises ved feil innlogging.

- **Kryptering:**  
  Passordene krypteres med `bcrypt` før de lagres i databasen, slik at sensitiv informasjon forblir beskyttet selv om databasen blir kompromittert.

- **Database:**  
  Brukerinformasjon lagres i en relasjonsdatabase (f.eks. PostgreSQL). Det benyttes tiltak for å hindre SQL-injeksjon og andre sikkerhetsrisikoer, som parameteriserte spørringer.

- **Sikkerhet:**  
  - Implementering av HTTPS for å sikre kryptert kommunikasjon.
  - Beskyttelse mot brute force-angrep ved å begrense antall innloggingsforsøk.
  - Beskyttelse mot session hijacking ved å sikre og validere session cookies.
  - CSRF-beskyttelse (Cross-Site Request Forgery) er også inkludert for å forhindre ondsinnede forespørsler.

- **Brukergrensesnitt:**  
  En enkel og intuitiv påloggingsside med klare og lettforståelige feilmeldinger ved feil innlogging.

## Teknologier

- **Backend:** Python (Flask)
- **Database:** PostgreSQL
- **Kryptering:** bcrypt
- **Frontend:** HTML, CSS, JavaScript, Tailwind CSS
- **Sikkerhet:** HTTPS, CSRF-beskyttelse

## Komme i gang

### Forutsetninger

For å kjøre prosjektet på din lokale maskin, må du ha følgende installert:

- Python (versjon 3.7 eller høyere)
- PostgreSQL
- pip (Python-pakkehåndterer)

### Installere avhengigheter

1. Klon dette prosjektet til din lokale maskin:
   ```bash
   git clone <repo-url>
   cd <project-directory>
