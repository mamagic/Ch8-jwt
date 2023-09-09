package tacos.web.api;

import java.util.Date;
import java.util.List;

import org.springframework.hateoas.CollectionModel;
import org.springframework.hateoas.EntityModel;
import org.springframework.hateoas.RepresentationModel;
import org.springframework.hateoas.server.core.Relation;

import lombok.Getter;
import tacos.Taco;

@Relation(value="taco", collectionRelation="tacos")
public class TacoResource extends EntityModel<TacoResource> {

  private static final IngredientResourceAssembler 
            ingredientAssembler = new IngredientResourceAssembler();
  
  @Getter
  private final String name;

  @Getter
  private final Date createdAt;

  @Getter
  private final List<IngredientResource> ingredients;
  
  public TacoResource(Taco taco) {
    this.name = taco.getName();
    this.createdAt = taco.getCreatedAt();
    
    CollectionModel<IngredientResource> ingredientResource =  
            ingredientAssembler.toCollectionModel(taco.getIngredients());
    
    this.ingredients = (List<IngredientResource>) ingredientResource.getContent();
    
//	    this.ingredients = 
//	        ingredientAssembler.toCollectionModel(taco.getIngredients()).getContent();
  }
  
}