def calculate_padding(result, sign_coord, decimals=4):
    # Calculate the minimum and maximum x and y coordinates of the sign
    min_x = min(coord[0] for coord in sign_coord)
    max_x = max(coord[0] for coord in sign_coord)
    min_y = min(coord[1] for coord in sign_coord)
    max_y = max(coord[1] for coord in sign_coord)

    # Calculate the minimum and maximum x and y coordinates of the result
    result_min_x = min(coord[0] for coord in result)
    result_max_x = max(coord[0] for coord in result)
    result_min_y = min(coord[1] for coord in result)
    result_max_y = max(coord[1] for coord in result)

    # Calculate the padding values
    left_padding = round(min_x - result_min_x, decimals)
    right_padding = round(result_max_x - max_x, decimals)
    top_padding = round(min_y - result_min_y, decimals)
    bottom_padding = round(result_max_y - max_y, decimals)

    # Create the padding list
    padding = [
        (left_padding, top_padding),
        (right_padding, top_padding),
        (right_padding, bottom_padding),
        (left_padding, bottom_padding)
    ]

    return padding

# Example usage
result = [(0.4138883650302887, 0.9000649452209473),
          (0.4640933573246002, 0.9000737071037292),
          (0.4640996754169464, 0.9097864627838135),
          (0.41389450430870056, 0.9097775816917419)]

sign_coord = [(0.2317812442779541, 0.7981478571891785),
              (0.3849175274372101, 0.7981717586517334),
              (0.3849300146102905, 0.8182522654533386),
              (0.23179274797439575, 0.8182277679443359)]

padding = calculate_padding(result, sign_coord)
print("Padding values:", padding)