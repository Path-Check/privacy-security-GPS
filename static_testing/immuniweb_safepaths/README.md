I've reviewed this report from immunoweb.  I've raised the following:

* [SAF-267](https://pathcheck.atlassian.net/browse/SAF-267) which is a task to review the code or dynamic behaviour of one of our dependencies, that may be writing location data to a temporary file in a non-secure way.
* There's a number of 3rd party services which may, or may not need better protection.  I'm not sure about this so asked for help on #fn_security and had confirmation they are necessary and appropriate.
* Regarding clear text traffic I've raised [SAF-265](https://pathcheck.atlassian.net/browse/SAF-265) - note that this needs input from @diarmidmackenzie on timing as it may break current test methods.  Additionally note that giving this permission doesn't mean we will actually be using clear text, as that is controlled presumably from the HA yaml file.
* We should remove Android permission to use external storage - [SAF-264](https://pathcheck.atlassian.net/browse/SAF-264)
* The intersection data logging is not protected - log statements need to be removed - [SAF-236](https://pathcheck.atlassian.net/browse/SAF-236)

I've reviewed for sensitive hardcodings in our code, and specifically around the Android RealmDB implementation and I'm happy.  There's a lot of false positives flagged up by the report.  We may be vulnerable around particular 3rd party dependencies.

Is there anyone who can do a low-level data flow diagram to identify which dependencies are of priority concern?

Finally, I had a look at the use of random numbers and wasn't concerned about any of them, however with all of this, a peer review would be great.
