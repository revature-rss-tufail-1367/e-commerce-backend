/**
 * A Request DTO that will be used to send Password reset requests for the contained email from the front end.
 */

package com.revature.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;



@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResetRequestEmail {
    private String email;

}
