use crate::cli;

pub fn substitute_email_params(template: String, args: &cli::Args) -> String {
    let template = template.clone();
    let template = template.replace("{user}", &args.user);
    let template = template.replace("{from}", &args.from);
    let template = template.replace("{to}", &args.to);
    let template = template.replace("{from_first_name}", &args.from_first_name);
    let template = template.replace("{contact_name}", &args.contact_name);

    return template;
}
