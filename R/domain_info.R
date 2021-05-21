#' domains_info
#'
#' A function that returns Whois data about a given list domain names
#'
#' @param domains A comma separated string of domain names
#' @param excludes A comma separated string of domain names to esclude from search
#'
#' @return A data.frame with info about the given domains
#'
#' @examples
#'  info <- domains_info(
#'    domains = "domain1.com, domain2.com, domain3.com",
#'    excludes="domain2.com)
#'
#' @export
#'
domains_info <- function(domains, excludes="google.com, facebook.com, youtube.com") {
  # Check input parameters
  if (missing(domains)) {
    stop("The function requires the parameter 'domains'!")
  }
  if (!is.character(domains) || domains == "") {
    stop("The parameter 'domains' must be a non empty string!")
  }
  if (!is.character(excludes) || excludes == "") {
    stop("The parameter 'excludes' must be a non empty string!")
  }

  # Split domains and excludes in lists
  domains <- unique(strsplit(domains, "\\s*,\\s*")[[1]])
  excludes <- unique(strsplit(excludes, "\\s*,\\s*")[[1]])
  # Remove all excluded elements form domains
  domains <- setdiff(domains, excludes)

  # Create empty result data frame
  domain_df <- data.frame(
    domain_name=character(),
    type=character(),
    created_date=character(),
    updated_date=character(),
    expire_date=character(),
    status=character(),
    registrat_contact=data.frame(
      name=character(),
      organization=character(),
      country=character(),
      state=character(),
      city=character(),
      street=character(),
      postal_code=character(),
      email=character(),
      telephone=character()
    ),
    administrative_contact=data.frame(
      name=character(),
      organization=character(),
      country=character(),
      state=character(),
      city=character(),
      street=character(),
      postal_code=character(),
      email=character(),
      telephone=character()
    ),
    technical_contact=data.frame(
      name=character(),
      organization=character(),
      country=character(),
      state=character(),
      city=character(),
      street=character(),
      postal_code=character(),
      email=character(),
      telephone=character()
    )
  )

  for (name in domains) {
    domain_df <- rbind(domain_df, get_single_domain_info(name))
  }

  return(domain_df)
}

#' get_single_domain_info
#'
#' A function that returns all the info about a single domain
#'
#' @param name the name of the domain to search
#'
#' @return A data.frame with info about the given domain name
#'
#' @examples
#'  info <- get_single_domain_info(name="domain1.com")
#'
get_single_domain_info <- function(name) {
  cat(paste0("Getting info about domain ", name, "...\n"))

  # Get the json data from whois API
  json_response <- get_dummy_json_data()
  json_response <- json_response[["records"]]

  # Create the result data.frame with all the data
  result <-data.frame(
    domain_name=toString(json_response$domainName),
    type=toString(json_response$domainType),
    created_date=toString(json_response$createdDateISO8601),
    updated_date=toString(json_response$updatedDateISO8601),
    expire_date=toString(json_response$expiresDateISO8601),
    status=toString(json_response$status),
    registrat_contact=data.frame(
      name=toString(json_response$registrantContact.name),
      organization=toString(json_response$registrantContact.organization),
      country=toString(json_response$registrantContact.country),
      state=toString(json_response$registrantContact.state),
      city=toString(json_response$registrantContact.city),
      street=toString(json_response$registrantContact.street),
      postal_code=toString(json_response$registrantContact.postalCode),
      email=toString(json_response$registrantContact.email),
      telephone=toString(json_response$registrantContact.telephone)
    ),
    administrative_contact=data.frame(
      name=toString(json_response$administrativeContact.name),
      organization=toString(json_response$administrativeContact.organization),
      country=toString(json_response$administrativeContact.country),
      state=toString(json_response$administrativeContact.state),
      city=toString(json_response$administrativeContact.city),
      street=toString(json_response$administrativeContact.street),
      postal_code=toString(json_response$administrativeContact.postalCode),
      email=toString(json_response$administrativeContact.email),
      telephone=toString(json_response$administrativeContact.telephone)
    ),
    technical_contact=data.frame(
      name=toString(json_response$technicalContact.name),
      organization=toString(json_response$technicalContact.organization),
      country=toString(json_response$technicalContact.country),
      state=toString(json_response$technicalContact.state),
      city=toString(json_response$technicalContact.city),
      street=toString(json_response$technicalContact.street),
      postal_code=toString(json_response$technicalContact.postalCode),
      email=toString(json_response$technicalContact.email),
      telephone=toString(json_response$technicalContact.telephone)
    ))

  return(result)

}

get_dummy_json_data <- function() {
  data <- fromJSON("fatto_domain_response.json", flatten = TRUE)
}
