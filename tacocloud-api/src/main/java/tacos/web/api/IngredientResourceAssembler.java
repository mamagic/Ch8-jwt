package tacos.web.api;

import org.springframework.hateoas.server.mvc.RepresentationModelAssemblerSupport;

import tacos.Ingredient;

class IngredientResourceAssembler extends 
          RepresentationModelAssemblerSupport<Ingredient, IngredientResource> {

  public IngredientResourceAssembler() {
    super(IngredientController.class, IngredientResource.class);
  }

  @Override
  public IngredientResource toModel(Ingredient ingredient) {
    return createModelWithId(ingredient.getId(), ingredient);
  }
  
  @Override
  protected IngredientResource instantiateModel(Ingredient ingredient) {
    return new IngredientResource(ingredient);
  }

}



//package tacos.web.api;
//
//import org.springframework.hateoas.mvc.ResourceAssemblerSupport;
//
//import tacos.Ingredient;
//
//class IngredientResourceAssembler extends 
//          ResourceAssemblerSupport<Ingredient, IngredientResource> {
//
//  public IngredientResourceAssembler() {
//    super(IngredientController.class, IngredientResource.class);
//  }
//
//  @Override
//  public IngredientResource toResource(Ingredient ingredient) {
//    return createResourceWithId(ingredient.getId(), ingredient);
//  }
//  
//  @Override
//  protected IngredientResource instantiateResource(
//                                            Ingredient ingredient) {
//    return new IngredientResource(ingredient);
//  }
//
//}