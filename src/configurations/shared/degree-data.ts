import type { JsonRecord } from "../../types.js";

export const DEGREE_CREDENTIAL_SUBJECT: JsonRecord = {
  name: "Arthur Dent",
  address: {
    street_address: "42 Market Street",
    locality: "Milliways",
    postal_code: "12345",
  },
  degrees: [
    {
      type: "Bachelor of Science",
      university: "University of Betelgeuse",
    },
    {
      type: "Master of Science",
      university: "University of Betelgeuse",
    },
    {
      university: "University of Betelgeuse",
    },
  ],
  academic_programmes: [["Bachelor of Science"], ["Master of Science", "Doctor of Philosophy"]],
  nationalities: ["British", "Betelgeusian"],
};
