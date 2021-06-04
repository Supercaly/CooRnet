#' get_domains_from_summary
#'
#' A function that returns domains info from a summary data.frame
#'
#' @param summary A data.frame produced by get_component_summary or get_cluster_summary
#' @param threshold A value between 0 and 1 used to filter the summary by
#'                  their gini.parent_domain
#' @param limit Limit the number of domains searched for each component
#'
#' @return A data.frame with info about the given domains and associated
#'         component from summary
#'
get_domains_from_summary <- function(summary, threshold=0.8, limit=5) {
  # Filter all summary with gini > threshold
  coord_domains <- summary %>%
    dplyr::filter(gini.parent_domain > threshold) %>%
    dplyr::select(c(component, top.parent_domain))

  # Get info about the domains in each component
  result <- get_empty_result_data()
  for (i in 1:nrow(coord_domains)) {
    cat(paste0(i,"/",nrow(coord_domains),"\n"))

    # Limit the search to only first limit domains
    domains_to_search <- head(strsplit(
      coord_domains$top.parent_domain[i], "\\s*,\\s*")[[1]], limit)
    domains_to_search <- paste(domains_to_search, collapse = ", ")
    domains_info_res <- get_domains_info(domains_to_search)
    # Add to result a component column
    result <- rbind(result, dplyr::mutate(
      domains_info_res,
      component=coord_domains$component[i]))
  }

  return(result)
}

#' get_domains_info
#'
#' A function that returns Whois data about a given list of domain names
#'
#' @param domains A comma separated string of domain names
#' @param excludes A comma separated string of domain names to exclude from search
#' @param history If set to true returns the history data using the Whois API,
#'                otherwise it returns the raw data
#'
#' @return A data.frame with info about the given domains
#'
#' @details to start using the library you need to set the Whois API key.
#'   Open the environment variable file with file.edit("~/.Renviron"),
#'   write WHOIS_API_KEY = <YOUR_API_KEY>, save the file and restart your current R session to start using the Whois API
#'
#' @examples
#'  info <- domains_info(
#'    domains = "domain1.com, domain2.com, domain3.com",
#'    excludes="domain2.com",
#'    history=TRUE)
#'
#'  info2 <- domains_info(
#'    domains = "domain1.com, domain2.com, domain3.com",
#'    excludes="domain2.com")
#'
get_domains_info <- function(domains, excludes="google.com, facebook.com, youtube.com", history=FALSE) {
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
  # Remove all excluded elements form domains and all empty strings
  domains <- setdiff(domains, excludes)
  domains <- domains[domains != ""]

  # If history is FALSE get the raw data otherwise use
  # the history remote APIs
  if (!history) {
    domain_df <- get_bulk_raw_domain_info(domains)
  } else {
    domain_df <- get_empty_result_data()
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
  json_response <- get_domain_info_from_api(name)
  if (is.null(json_response)) {
    return(get_na_result_data())
  }

  # Create the result data.frame with all the data
  return(data.frame(
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
    raw_data=NA))
}

#' get_bulk_raw_domain_info
#'
#' A function that returns raw info about a list of domain
#' using direct calls to Whois servers
#'
#' @param domain_names a list of domain names to search
#'
#' @return A data.frame with info about the given domain names
#'         Note: all fields of the data.frame are set to NA except
#'         for raw_data
#'
#' @examples
#'   info <- get_bulk_raw_domain_info("domain1.com, domain2.com")
#'
get_bulk_raw_domain_info <- function(domain_names) {
  # Check parameters
  if (!is.character(domain_names)) {
    stop("'domain_names' is not a character list!")
  }
  # If domain_names is empty exit this function returning
  # an empty data.frame
  if (length(domain_names) == 0 || domain_names == "") {
    cat("No domains to search...\n")
    return(get_empty_result_data())
  }

  cat(paste0("Getting info about domains ", paste(domain_names, collapse = ", "), "...\n"))

  # Get info about each domain name
  result <- get_empty_result_data()
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

      # Strip all lines starting with % and *
      raw_data <- raw_data[!substr(raw_data, 1, 1) %in% c("*", "%")]

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
      raw_data=raw_data))
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
#' @return A string with the raw domain info or NA if
#'         there was an error
#'
get_raw_domain_info <- function(hostname, server) {
  # Get data from server
  conn <- make.socket(server, 43)

  return(tryCatch({
    # Write the hostname to the socket
    write.socket(conn, hostname)
    write.socket(conn, "\r\n")

    data <- ""
    curr_read <- "x"

    # Read the server's response
    while(curr_read != "") {
      curr_read <- read.socket(conn)
      data <- paste0(data, curr_read)
    }

    # If there was an error return NA instead of the default error message
    if (length(grep("This query returned 0 objects", data, value = TRUE)) != 0) {
      data <- NA
    }

    return(data)
  }, error = function(err) {
    cat(paste0("Error reading info for domain '",hostname, "' on server '", server,"'\n"))
    return(NA)
  }, finally = close.socket(conn)))
}

#' get_domain_info_from_api
#'
#' A function that returns the domain info obtained
#' from the Whois API
#'
#' @param hostname the domain name to search
#'
#' @return a data.frame with the response content or NULL
#'         if the server responded with a status that's
#'         not 200
#' @importFrom httr POST status_code content
#'
get_domain_info_from_api <- function(hostname) {
  res <- httr::POST(
    "http://localhost:5000/api/v1",
    #"https://whois-history.whoisxmlapi.com/api/v1",
    body = list(
      apiKey=Sys.getenv("WHOIS_API_KEY"),
      domainName=hostname,
      mode="purchase"
    ),
    encode = "json")

  res_status <- httr::status_code(res)

  # Check status code for errors
  if (res_status == 401) {
    stop(paste0(
      "Error retrieving domain info from Whois server: ",
      "The provided API Key is not valid, ",
      "check that the value of WHOIS_API_KEY in .Renviron is correct."))
  }
  if (res_status != 200) {
    cat(paste0("Error retrieving domain info from Whois server! status: '", res_status,"'"))
    return(NULL)
  }

  content <- httr::content(res, as="text", encoding = "UTF-8")
  json_content <- fromJSON(content, flatten = TRUE)[["records"]]
  return(json_content)
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

#' get_na_result_data
#'
#' A function that returns a return data.frame with all NA values
#'
#' @return A data.frame
#'
get_na_result_data <- function() {
  return(data.frame(
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
    raw_data=NA
  ))
}
