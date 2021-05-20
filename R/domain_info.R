#' domains_info
#'
#' A function that returns Whois data about a given list domain names
#'
#' @param domains A vector of domain names
#'
#' @return A data.frame with info about the given domains
#'
#' @examples
#'  info <- domains_info(domains = c("google.com"))
#'
#' @export
#'
domains_info <- function(domains) {
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
    domain_df <- rbind(domain_df, get_single_domain_info(""))
  }

  return(domain_df)
}

get_single_domain_info <- function(name) {
  # Get the json data from whois API
  json_response <- get_dummy_json_data()
  json_response <- json_response[["records"]]

  domainName <- toString(json_response$domainName)
  domainType <- toString(json_response$domainType)
  createdDate <- toString(json_response$createdDateISO8601)
  updatedDate <- toString(json_response$updatedDateISO8601)
  expiresDate <- toString(json_response$expiresDateISO8601)
  status <- toString(json_response$status)

  print(domainName)
  print(domainType)
  print(createdDate)
  print(updatedDate)
  print(expiresDate)
  print(status)

  result <-data.frame(domain_name=domainName,
                      type=domainType,
                      created_date=createdDate,
                      updated_date=updatedDate,
                      expire_date=expiresDate,
                      status=status,
                      registrat_contact=data.frame(
                        name="aa",
                        organization="bb",
                        country="cc",
                        state="dd",
                        city="ee",
                        street="ff",
                        postal_code="gg",
                        email="hh",
                        telephone="ii"
                        ))
  return(result)

}

get_dummy_json_data <- function() {
  data <- fromJSON("fatto_domain_response.json", flatten = TRUE)
}
