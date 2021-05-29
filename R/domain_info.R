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
#'    excludes="domain2.com")
#'
#' @export
#'
#' TODO: Rename parameter payed to history
domains_info <- function(domains, excludes="google.com, facebook.com, youtube.com", payed=FALSE) {
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
  domain_df <- get_empty_result_data()

  # If payed is FALSE use Rwhois package otherwise use
  # the payed remote APIs
  if (!payed) {
    domain_df <- get_free_bulk_domain_info(domains)
  } else {
    # TODO: Replace this loop with a more efficent function
    for (name in domains) {
      domain_df <- rbind(domain_df, get_single_domain_info(name))
    }
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
  # TODO: Use real API calls
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
    ),
    raw_data=NA)

  return(result)

}

#' get_free_bulk_domain_info
#'
#' A function that returns all the info about a list of domain
#' using the Rwhois package
#'
#' @param domain_names a list of domain names to search
#'
#' @return A data.frame with info about the given domain names
#'
#' @examples
#'   info <- get_free_bulk_domain_info("domain1.com")
#'
get_free_bulk_domain_info <- function(domain_names) {
  # Check parameters
  if (!is.character(domain_names)) {
    stop("'domain_names' is not a character list!")
  }
  # If domain_names is empty exit this function
  if (length(domain_names) == 0 || domain_names == "") {
    cat("No domains to search...\n")
    return(NULL)
  }

  result <- get_empty_result_data()

  cat(paste0("Getting info about domains ", paste(domain_names, collapse = ", "), "...\n"))

  for (host in domain_names) {
    raw_data <- NA
    # Get recursively the info about the domain
    refer = "whois.iana.org"
    while(length(refer) != 0) {
      raw_data <- get_raw_domain_info(hostname = host, server = refer)
      # If the raw domain is NA exit the loop
      if (is.na(raw_data)) {
        break
      }
      raw_data <- strsplit(raw_data, "\n")[[1]]
      refer <- gsub("refer:\\s*", "", raw_data[grep("^refer:", raw_data)])
      # TODO: Remove all lines with * and %
      raw_data <- paste(raw_data, collapse = "\n")
    }

    result <- rbind(result, data.frame(
      domain_name=NA,
      type=NA,
      created_date=NA,
      updated_date=NA,
      expire_date=NA,
      status=NA,
      registrat_contact=data.frame(
        name=NA,
        organization=NA,
        country=NA,
        state=NA,
        city=NA,
        street=NA,
        postal_code=NA,
        email=NA,
        telephone=NA
      ),
      administrative_contact=data.frame(
        name=NA,
        organization=NA,
        country=NA,
        state=NA,
        city=NA,
        street=NA,
        postal_code=NA,
        email=NA,
        telephone=NA
      ),
      technical_contact=data.frame(
        name=NA,
        organization=NA,
        country=NA,
        state=NA,
        city=NA,
        street=NA,
        postal_code=NA,
        email=NA,
        telephone=NA
      ),
      raw_data=raw_data)
      )
  }
  return(result)
}

#' get_raw_domain_info
#'
#' A function that returns info about a domain in a row format
#'
#' @param hostname the domain name to search
#' @param server the server address to use for the search
#'
#' @return A string with the raw domain info
#'
get_raw_domain_info <- function(hostname, server) {
  # Get data from server
  conn <- make.socket(server, 43)
  write.socket(conn, hostname)
  write.socket(conn, "\r\n")

  data <- ""
  curr_read <- "x"

  while(curr_read != "") {
    curr_read <- read.socket(conn)
    data <- paste0(data, curr_read)
  }

  close.socket(conn)

  # If there was an error return NA instead of the default error message
  if (length(grep("This query returned 0 objects", data, value = TRUE)) != 0) {
    return(NA)
  }

  return(data)
}

#' get_empty_result_data
#'
#' A function that returns a empty return data.frame
#'
#' @return A data.frame
#'
get_empty_result_data <- function() {
  return(data.frame(
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
    ),
    raw_data=character()
  ))
}

get_dummy_json_data <- function() {
  data <- fromJSON("fatto_domain_response.json", flatten = TRUE)
}
